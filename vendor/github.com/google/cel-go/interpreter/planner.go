// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package interpreter

import (
	"fmt"

	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/packages"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter/functions"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// interpretablePlanner creates an Interpretable evaluation plan from a proto Expr value.
type interpretablePlanner interface {
	// Plan generates an Interpretable value (or error) from the input proto Expr.
	Plan(expr *exprpb.Expr) (Interpretable, error)
}

// newPlanner creates an interpretablePlanner which references a Dispatcher, TypeProvider,
// Packager, and CheckedExpr value. These pieces of data are used to resolve functions,
// types, and namespaced identifiers at plan time rather than at runtime since it only
// needs to be done once and may be semi-expensive to compute.
func newPlanner(disp Dispatcher,
	types ref.TypeProvider,
	pkg packages.Packager,
	checked *exprpb.CheckedExpr,
	decorators ...InterpretableDecorator) interpretablePlanner {
	return &planner{
		disp:       disp,
		types:      types,
		pkg:        pkg,
		identMap:   make(map[string]Interpretable),
		refMap:     checked.GetReferenceMap(),
		typeMap:    checked.GetTypeMap(),
		decorators: decorators,
	}
}

// newUncheckedPlanner creates an interpretablePlanner which references a Dispatcher,
// TypeProvider, and Packager to resolve functions and types at plan time. Namespaced isa
// present in Select expressions are resolved lazily at evaluation time.
func newUncheckedPlanner(disp Dispatcher,
	types ref.TypeProvider,
	pkg packages.Packager,
	decorators ...InterpretableDecorator) interpretablePlanner {
	return &planner{
		disp:       disp,
		types:      types,
		pkg:        pkg,
		identMap:   make(map[string]Interpretable),
		refMap:     make(map[int64]*exprpb.Reference),
		typeMap:    make(map[int64]*exprpb.Type),
		decorators: decorators,
	}
}

// planner is an implementatio of the interpretablePlanner interface.
type planner struct {
	disp       Dispatcher
	types      ref.TypeProvider
	pkg        packages.Packager
	identMap   map[string]Interpretable
	refMap     map[int64]*exprpb.Reference
	typeMap    map[int64]*exprpb.Type
	decorators []InterpretableDecorator
}

// Plan implements the interpretablePlanner interface. This implementation of the Plan method also
// applies decorators to each Interpretable generated as part of the overall plan. Decorators are
// useful for layering functionality into the evaluation that is not natively understood by CEL,
// such as state-tracking, expression re-write, and possibly efficient thread-safe memoization of
// repeated expressions.
func (p *planner) Plan(expr *exprpb.Expr) (Interpretable, error) {
	switch expr.ExprKind.(type) {
	case *exprpb.Expr_CallExpr:
		return p.decorate(p.planCall(expr))
	case *exprpb.Expr_IdentExpr:
		return p.decorate(p.planIdent(expr))
	case *exprpb.Expr_SelectExpr:
		return p.decorate(p.planSelect(expr))
	case *exprpb.Expr_ListExpr:
		return p.decorate(p.planCreateList(expr))
	case *exprpb.Expr_StructExpr:
		return p.decorate(p.planCreateStruct(expr))
	case *exprpb.Expr_ComprehensionExpr:
		return p.decorate(p.planComprehension(expr))
	case *exprpb.Expr_ConstExpr:
		return p.decorate(p.planConst(expr))
	}
	return nil, fmt.Errorf("unsupported expr: %v", expr)
}

// decorate applies the InterpretableDecorator functions to the given Interpretable.
// Both the Interpretable and error generated by a Plan step are accepted as arguments
// for convenience.
func (p *planner) decorate(i Interpretable, err error) (Interpretable, error) {
	if err != nil {
		return nil, err
	}
	for _, dec := range p.decorators {
		i, err = dec(i)
		if err != nil {
			return nil, err
		}
	}
	return i, nil
}

// planIdent creates an Interpretable that resolves an identifier from an Activation.
func (p *planner) planIdent(expr *exprpb.Expr) (Interpretable, error) {
	ident := expr.GetIdentExpr()
	idName := ident.Name
	i, found := p.identMap[idName]
	if found {
		return i, nil
	}
	i = &evalIdent{
		id:    expr.Id,
		name:  idName,
		types: p.types,
	}
	p.identMap[idName] = i
	return i, nil
}

// planSelect creates an Interpretable with either:
//  a) selects a field from a map or proto.
//  b) creates a field presence test for a select within a has() macro.
//  c) resolves the select expression to a namespaced identifier.
func (p *planner) planSelect(expr *exprpb.Expr) (Interpretable, error) {
	sel := expr.GetSelectExpr()
	// If the Select was marked TestOnly, this is a presence test.
	//
	// Note: presence tests are defined for structured (e.g. proto) and dynamic values (map, json)
	// as follows:
	//  - True if the object field has a non-default value, e.g. obj.str != ""
	//  - True if the dynamic value has the field defined, e.g. key in map
	//
	// However, presence tests are not defined for qualified identifier names with primitive types.
	// If a string named 'a.b.c' is declared in the environment and referenced within `has(a.b.c)`,
	// it is not clear whether has should error or follow the convention defined for structured
	// values.
	if sel.TestOnly {
		op, err := p.Plan(sel.GetOperand())
		if err != nil {
			return nil, err
		}
		return &evalTestOnly{
			id:    expr.Id,
			field: types.String(sel.Field),
			op:    op,
		}, nil
	}

	// If the Select id appears in the reference map from the CheckedExpr proto then it is either
	// a namespaced identifier or enum value.
	idRef, found := p.refMap[expr.Id]
	if found {
		idName := idRef.Name
		// If the reference has a value, this id represents an enum.
		if idRef.Value != nil {
			return p.Plan(&exprpb.Expr{Id: expr.Id,
				ExprKind: &exprpb.Expr_ConstExpr{
					ConstExpr: idRef.Value,
				}})
		}
		// If the identifier has already been encountered before, return the previous Iterable.
		i, found := p.identMap[idName]
		if found {
			return i, nil
		}
		// Otherwise, generate an evalIdent Interpretable.
		i = &evalIdent{
			id:   expr.Id,
			name: idName,
		}
		p.identMap[idName] = i
		return i, nil
	}

	// Lastly, create a field selection Interpretable.
	op, err := p.Plan(sel.GetOperand())
	if err != nil {
		return nil, err
	}
	return &evalSelect{
		id:        expr.Id,
		field:     types.String(sel.Field),
		op:        op,
		resolveID: p.idResolver(sel),
	}, nil
}

// planCall creates a callable Interpretable while specializing for common functions and invocation
// patterns. Specifically, conditional operators &&, ||, ?:, and (in)equality functions result in
// optimized Interpretable values.
func (p *planner) planCall(expr *exprpb.Expr) (Interpretable, error) {
	call := expr.GetCallExpr()
	fnName := call.Function
	fnDef, _ := p.disp.FindOverload(fnName)
	argCount := len(call.GetArgs())
	var offset int
	if call.Target != nil {
		argCount++
		offset++
	}
	args := make([]Interpretable, argCount, argCount)
	if call.Target != nil {
		arg, err := p.Plan(call.Target)
		if err != nil {
			return nil, err
		}
		args[0] = arg
	}
	for i, argExpr := range call.GetArgs() {
		arg, err := p.Plan(argExpr)
		if err != nil {
			return nil, err
		}
		args[i+offset] = arg
	}
	var oName string
	if oRef, found := p.refMap[expr.Id]; found &&
		len(oRef.GetOverloadId()) == 1 {
		oName = oRef.GetOverloadId()[0]
	}

	// Generate specialized Interpretable operators by function name if possible.
	switch fnName {
	case operators.LogicalAnd:
		return p.planCallLogicalAnd(expr, args)
	case operators.LogicalOr:
		return p.planCallLogicalOr(expr, args)
	case operators.Conditional:
		return p.planCallConditional(expr, args)
	case operators.Equals:
		return p.planCallEqual(expr, args)
	case operators.NotEquals:
		return p.planCallNotEqual(expr, args)
	}

	// Otherwise, generate Interpretable calls specialized by argument count.
	switch argCount {
	case 0:
		return p.planCallZero(expr, fnName, oName, fnDef)
	case 1:
		return p.planCallUnary(expr, fnName, oName, fnDef, args)
	case 2:
		return p.planCallBinary(expr, fnName, oName, fnDef, args)
	default:
		return p.planCallVarArgs(expr, fnName, oName, fnDef, args)
	}
}

// planCallZero generates a zero-arity callable Interpretable.
func (p *planner) planCallZero(expr *exprpb.Expr,
	function string,
	overload string,
	impl *functions.Overload) (Interpretable, error) {
	if impl == nil || impl.Function == nil {
		return nil, fmt.Errorf("no such overload: %s()", function)
	}
	return &evalZeroArity{
		id:   expr.Id,
		impl: impl.Function,
	}, nil
}

// planCallUnary generates a unary callable Interpretable.
func (p *planner) planCallUnary(expr *exprpb.Expr,
	function string,
	overload string,
	impl *functions.Overload,
	args []Interpretable) (Interpretable, error) {
	var fn functions.UnaryOp
	var trait int
	if impl != nil {
		if impl.Unary == nil {
			return nil, fmt.Errorf("no such overload: %s(arg)", function)
		}
		fn = impl.Unary
		trait = impl.OperandTrait
	}
	return &evalUnary{
		id:       expr.Id,
		function: function,
		overload: overload,
		arg:      args[0],
		trait:    trait,
		impl:     fn,
	}, nil
}

// planCallBinary generates a binary callable Interpretable.
func (p *planner) planCallBinary(expr *exprpb.Expr,
	function string,
	overload string,
	impl *functions.Overload,
	args []Interpretable) (Interpretable, error) {
	var fn functions.BinaryOp
	var trait int
	if impl != nil {
		if impl.Binary == nil {
			return nil, fmt.Errorf("no such overload: %s(lhs, rhs)", function)
		}
		fn = impl.Binary
		trait = impl.OperandTrait
	}
	return &evalBinary{
		id:       expr.Id,
		function: function,
		overload: overload,
		lhs:      args[0],
		rhs:      args[1],
		trait:    trait,
		impl:     fn,
	}, nil
}

// planCallVarArgs generates a variable argument callable Interpretable.
func (p *planner) planCallVarArgs(expr *exprpb.Expr,
	function string,
	overload string,
	impl *functions.Overload,
	args []Interpretable) (Interpretable, error) {
	var fn functions.FunctionOp
	var trait int
	if impl != nil {
		if impl.Function == nil {
			return nil, fmt.Errorf("no such overload: %s(...)", function)
		}
		fn = impl.Function
		trait = impl.OperandTrait
	}
	return &evalVarArgs{
		id:       expr.Id,
		function: function,
		overload: overload,
		args:     args,
		trait:    trait,
		impl:     fn,
	}, nil
}

// planCallEqual generates an equals (==) Interpretable.
func (p *planner) planCallEqual(expr *exprpb.Expr,
	args []Interpretable) (Interpretable, error) {
	return &evalEq{
		id:  expr.Id,
		lhs: args[0],
		rhs: args[1],
	}, nil
}

// planCallNotEqual generates a not equals (!=) Interpretable.
func (p *planner) planCallNotEqual(expr *exprpb.Expr,
	args []Interpretable) (Interpretable, error) {
	return &evalNe{
		id:  expr.Id,
		lhs: args[0],
		rhs: args[1],
	}, nil
}

// planCallLogicalAnd generates a logical and (&&) Interpretable.
func (p *planner) planCallLogicalAnd(expr *exprpb.Expr,
	args []Interpretable) (Interpretable, error) {
	return &evalAnd{
		id:  expr.Id,
		lhs: args[0],
		rhs: args[1],
	}, nil
}

// planCallLogicalOr generates a logical or (||) Interpretable.
func (p *planner) planCallLogicalOr(expr *exprpb.Expr,
	args []Interpretable) (Interpretable, error) {
	return &evalOr{
		id:  expr.Id,
		lhs: args[0],
		rhs: args[1],
	}, nil
}

// planCallConditional generates a conditional / ternary (c ? t : f) Interpretable.
func (p *planner) planCallConditional(expr *exprpb.Expr,
	args []Interpretable) (Interpretable, error) {
	return &evalConditional{
		id:     expr.Id,
		expr:   args[0],
		truthy: args[1],
		falsy:  args[2],
	}, nil
}

// planCreateList generates a list construction Interpretable.
func (p *planner) planCreateList(expr *exprpb.Expr) (Interpretable, error) {
	list := expr.GetListExpr()
	elems := make([]Interpretable, len(list.GetElements()), len(list.GetElements()))
	for i, elem := range list.GetElements() {
		elemVal, err := p.Plan(elem)
		if err != nil {
			return nil, err
		}
		elems[i] = elemVal
	}
	return &evalList{
		id:    expr.Id,
		elems: elems,
	}, nil
}

// planCreateStruct generates a map or object construction Interpretable.
func (p *planner) planCreateStruct(expr *exprpb.Expr) (Interpretable, error) {
	str := expr.GetStructExpr()
	if len(str.MessageName) != 0 {
		return p.planCreateObj(expr)
	}
	entries := str.GetEntries()
	keys := make([]Interpretable, len(entries))
	vals := make([]Interpretable, len(entries))
	for i, entry := range entries {
		keyVal, err := p.Plan(entry.GetMapKey())
		if err != nil {
			return nil, err
		}
		keys[i] = keyVal

		valVal, err := p.Plan(entry.GetValue())
		if err != nil {
			return nil, err
		}
		vals[i] = valVal
	}
	return &evalMap{
		id:   expr.Id,
		keys: keys,
		vals: vals,
	}, nil
}

// planCreateObj generates an object construction Interpretable.
func (p *planner) planCreateObj(expr *exprpb.Expr) (Interpretable, error) {
	obj := expr.GetStructExpr()
	typeName := obj.MessageName
	var defined bool
	for _, qualifiedTypeName := range p.pkg.ResolveCandidateNames(typeName) {
		if _, found := p.types.FindType(qualifiedTypeName); found {
			typeName = qualifiedTypeName
			defined = true
			break
		}
	}
	if !defined {
		return nil, fmt.Errorf("unknown type: %s", typeName)
	}
	entries := obj.GetEntries()
	fields := make([]string, len(entries))
	vals := make([]Interpretable, len(entries))
	for i, entry := range entries {
		fields[i] = entry.GetFieldKey()
		val, err := p.Plan(entry.GetValue())
		if err != nil {
			return nil, err
		}
		vals[i] = val
	}
	return &evalObj{
		id:       expr.Id,
		typeName: typeName,
		fields:   fields,
		vals:     vals,
		types:    p.types,
	}, nil
}

// planComprehension generates an Interpretable fold operation.
func (p *planner) planComprehension(expr *exprpb.Expr) (Interpretable, error) {
	fold := expr.GetComprehensionExpr()
	accu, err := p.Plan(fold.GetAccuInit())
	if err != nil {
		return nil, err
	}
	iterRange, err := p.Plan(fold.GetIterRange())
	if err != nil {
		return nil, err
	}
	cond, err := p.Plan(fold.GetLoopCondition())
	if err != nil {
		return nil, err
	}
	step, err := p.Plan(fold.GetLoopStep())
	if err != nil {
		return nil, err
	}
	result, err := p.Plan(fold.GetResult())
	if err != nil {
		return nil, err
	}
	return &evalFold{
		id:        expr.Id,
		accuVar:   fold.AccuVar,
		accu:      accu,
		iterVar:   fold.IterVar,
		iterRange: iterRange,
		cond:      cond,
		step:      step,
		result:    result,
	}, nil
}

// planConst generates a constant valued Interpretable.
func (p *planner) planConst(expr *exprpb.Expr) (Interpretable, error) {
	val, err := p.constValue(expr.GetConstExpr())
	if err != nil {
		return nil, err
	}
	return &evalConst{
		id:  expr.Id,
		val: val,
	}, nil
}

// constValue converts a proto Constant value to a ref.Value.
func (p *planner) constValue(c *exprpb.Constant) (ref.Value, error) {
	switch c.ConstantKind.(type) {
	case *exprpb.Constant_BoolValue:
		return types.Bool(c.GetBoolValue()), nil
	case *exprpb.Constant_BytesValue:
		return types.Bytes(c.GetBytesValue()), nil
	case *exprpb.Constant_DoubleValue:
		return types.Double(c.GetDoubleValue()), nil
	case *exprpb.Constant_Int64Value:
		return types.Int(c.GetInt64Value()), nil
	case *exprpb.Constant_NullValue:
		return types.Null(c.GetNullValue()), nil
	case *exprpb.Constant_StringValue:
		return types.String(c.GetStringValue()), nil
	case *exprpb.Constant_Uint64Value:
		return types.Uint(c.GetUint64Value()), nil
	}
	return nil, fmt.Errorf("unknown constant type: %v", c)
}

// idResolver returns a function that resolves a Select expression to an identifier or field
// selection based on the operand being of Unknown type.
func (p *planner) idResolver(sel *exprpb.Expr_Select) func(Activation) (ref.Value, bool) {
	// TODO: ensure id resolution prefers the most specific identifier rather than the least
	// specific to be consistent with the check id resolution.
	validIdent := true
	resolvedIdent := false
	ident := sel.Field
	op := sel.Operand
	for validIdent && !resolvedIdent {
		switch op.ExprKind.(type) {
		case *exprpb.Expr_IdentExpr:
			ident = op.GetIdentExpr().Name + "." + ident
			resolvedIdent = true
			break
		case *exprpb.Expr_SelectExpr:
			nested := op.GetSelectExpr()
			ident = nested.GetField() + "." + ident
			op = nested.Operand
		default:
			validIdent = false
		}
	}
	return func(ctx Activation) (ref.Value, bool) {
		for _, id := range p.pkg.ResolveCandidateNames(ident) {
			if object, found := ctx.ResolveName(id); found {
				return object, found
			}
			if typeIdent, found := p.types.FindIdent(id); found {
				return typeIdent, found
			}
		}
		return nil, false
	}
}

type evalIdent struct {
	id    int64
	name  string
	types ref.TypeProvider
}

// ID implements the Interpretable interface method.
func (id *evalIdent) ID() int64 {
	return id.id
}

// Eval implements the Interpretable interface method.
func (id *evalIdent) Eval(ctx Activation) ref.Value {
	val, found := ctx.ResolveName(id.name)
	if found {
		return val
	}
	typeVal, found := id.types.FindIdent(id.name)
	if found {
		return typeVal
	}
	return types.Unknown{id.id}

}

type evalSelect struct {
	id        int64
	op        Interpretable
	field     types.String
	resolveID func(Activation) (ref.Value, bool)
}

// ID implements the Interpretable interface method.
func (sel *evalSelect) ID() int64 {
	return sel.id
}

// Eval implements the Interpretable interface method.
func (sel *evalSelect) Eval(ctx Activation) ref.Value {
	obj := sel.op.Eval(ctx)
	indexer, ok := obj.(traits.Indexer)
	if !ok {
		resolve, ok := sel.resolveID(ctx)
		if !ok {
			return types.ValOrErr(obj, "invalid type for field selection.")
		}
		return resolve
	}
	return indexer.Get(sel.field)
}

type evalTestOnly struct {
	id    int64
	op    Interpretable
	field types.String
}

// ID implements the Interpretable interface method.
func (test *evalTestOnly) ID() int64 {
	return test.id
}

// Eval implements the Interpretable interface method.
func (test *evalTestOnly) Eval(ctx Activation) ref.Value {
	obj := test.op.Eval(ctx)
	tester, ok := obj.(traits.FieldTester)
	if ok {
		return tester.IsSet(test.field)
	}
	container, ok := obj.(traits.Container)
	if ok {
		return container.Contains(test.field)
	}
	return types.ValOrErr(obj, "invalid type for field selection.")

}

type evalConst struct {
	id  int64
	val ref.Value
}

// ID implements the Interpretable interface method.
func (cons *evalConst) ID() int64 {
	return cons.id
}

// Eval implements the Interpretable interface method.
func (cons *evalConst) Eval(ctx Activation) ref.Value {
	return cons.val
}

type evalOr struct {
	id  int64
	lhs Interpretable
	rhs Interpretable
}

// ID implements the Interpretable interface method.
func (or *evalOr) ID() int64 {
	return or.id
}

// Eval implements the Interpretable interface method.
func (or *evalOr) Eval(ctx Activation) ref.Value {
	// short-circuit lhs.
	lVal := or.lhs.Eval(ctx)
	lBool, lok := lVal.(types.Bool)
	if lok && lBool == types.True {
		return types.True
	}
	// short-circuit on rhs.
	rVal := or.rhs.Eval(ctx)
	rBool, rok := rVal.(types.Bool)
	if rok && rBool == types.True {
		return types.True
	}
	// return if both sides are bool false.
	if lok && rok {
		return types.False
	}
	// TODO: return both values as a set if both are unknown or error.
	// prefer left unknown to right unknown.
	if types.IsUnknown(lVal) {
		return lVal
	}
	if types.IsUnknown(rVal) {
		return rVal
	}
	// if the left-hand side is non-boolean return it as the error.
	return types.ValOrErr(lVal, "no such overload")
}

type evalAnd struct {
	id  int64
	lhs Interpretable
	rhs Interpretable
}

// ID implements the Interpretable interface method.
func (and *evalAnd) ID() int64 {
	return and.id
}

// Eval implements the Interpretable interface method.
func (and *evalAnd) Eval(ctx Activation) ref.Value {
	// short-circuit lhs.
	lVal := and.lhs.Eval(ctx)
	lBool, lok := lVal.(types.Bool)
	if lok && lBool == types.False {
		return types.False
	}
	// short-circuit on rhs.
	rVal := and.rhs.Eval(ctx)
	rBool, rok := rVal.(types.Bool)
	if rok && rBool == types.False {
		return types.False
	}
	// return if both sides are bool true.
	if lok && rok {
		return types.True
	}
	// TODO: return both values as a set if both are unknown or error.
	// prefer left unknown to right unknown.
	if types.IsUnknown(lVal) {
		return lVal
	}
	if types.IsUnknown(rVal) {
		return rVal
	}
	// if the left-hand side is non-boolean return it as the error.
	return types.ValOrErr(lVal, "no such overload")
}

type evalConditional struct {
	id     int64
	expr   Interpretable
	truthy Interpretable
	falsy  Interpretable
}

// ID implements the Interpretable interface method.
func (cond *evalConditional) ID() int64 {
	return cond.id
}

// Eval implements the Interpretable interface method.
func (cond *evalConditional) Eval(ctx Activation) ref.Value {
	condVal := cond.expr.Eval(ctx)
	condBool, ok := condVal.(types.Bool)
	if !ok {
		return types.ValOrErr(condVal, "no such overload")
	}
	if condBool {
		return cond.truthy.Eval(ctx)
	}
	return cond.falsy.Eval(ctx)
}

type evalEq struct {
	id  int64
	lhs Interpretable
	rhs Interpretable
}

// ID implements the Interpretable interface method.
func (eq *evalEq) ID() int64 {
	return eq.id
}

// Eval implements the Interpretable interface method.
func (eq *evalEq) Eval(ctx Activation) ref.Value {
	lVal := eq.lhs.Eval(ctx)
	rVal := eq.rhs.Eval(ctx)
	return lVal.Equal(rVal)
}

type evalNe struct {
	id  int64
	lhs Interpretable
	rhs Interpretable
}

// ID implements the Interpretable interface method.
func (ne *evalNe) ID() int64 {
	return ne.id
}

// Eval implements the Interpretable interface method.
func (ne *evalNe) Eval(ctx Activation) ref.Value {
	lVal := ne.lhs.Eval(ctx)
	rVal := ne.rhs.Eval(ctx)
	eqVal := lVal.Equal(rVal)
	eqBool, ok := eqVal.(types.Bool)
	if !ok {
		if types.IsUnknown(eqVal) {
			return eqVal
		}
		return types.NewErr("no such overload: _!=_")
	}
	return !eqBool
}

type evalZeroArity struct {
	id   int64
	impl functions.FunctionOp
}

// ID implements the Interpretable interface method.
func (zero *evalZeroArity) ID() int64 {
	return zero.id
}

// Eval implements the Interpretable interface method.
func (zero *evalZeroArity) Eval(ctx Activation) ref.Value {
	return zero.impl()
}

type evalUnary struct {
	id       int64
	function string
	overload string
	arg      Interpretable
	trait    int
	impl     functions.UnaryOp
}

// ID implements the Interpretable interface method.
func (un *evalUnary) ID() int64 {
	return un.id
}

// Eval implements the Interpretable interface method.
func (un *evalUnary) Eval(ctx Activation) ref.Value {
	argVal := un.arg.Eval(ctx)
	// Early return if the argument to the function is unknown or error.
	if types.IsUnknownOrError(argVal) {
		return argVal
	}
	// If the implementation is bound and the argument value has the right traits required to
	// invoke it, then call the implementation.
	if un.impl != nil && (un.trait == 0 || argVal.Type().HasTrait(un.trait)) {
		return un.impl(argVal)
	}
	// Otherwise, if the argument is a ReceiverType attempt to invoke the receiver method on the
	// operand (arg0).
	if argVal.Type().HasTrait(traits.ReceiverType) {
		return argVal.(traits.Receiver).Receive(un.function, un.overload, []ref.Value{})
	}
	return types.NewErr("no such overload: %s", un.function)
}

type evalBinary struct {
	id       int64
	function string
	overload string
	lhs      Interpretable
	rhs      Interpretable
	trait    int
	impl     functions.BinaryOp
}

// ID implements the Interpretable interface method.
func (bin *evalBinary) ID() int64 {
	return bin.id
}

// Eval implements the Interpretable interface method.
func (bin *evalBinary) Eval(ctx Activation) ref.Value {
	lVal := bin.lhs.Eval(ctx)
	rVal := bin.rhs.Eval(ctx)
	// Early return if any argument to the function is unknown or error.
	if types.IsUnknownOrError(lVal) {
		return lVal
	}
	if types.IsUnknownOrError(rVal) {
		return rVal
	}
	// If the implementation is bound and the argument value has the right traits required to
	// invoke it, then call the implementation.
	if bin.impl != nil && (bin.trait == 0 || lVal.Type().HasTrait(bin.trait)) {
		return bin.impl(lVal, rVal)
	}
	// Otherwise, if the argument is a ReceiverType attempt to invoke the receiver method on the
	// operand (arg0).
	if lVal.Type().HasTrait(traits.ReceiverType) {
		return lVal.(traits.Receiver).Receive(bin.function, bin.overload, []ref.Value{rVal})
	}
	return types.NewErr("no such overload: %s", bin.function)
}

type evalVarArgs struct {
	id       int64
	function string
	overload string
	args     []Interpretable
	trait    int
	impl     functions.FunctionOp
}

// ID implements the Interpretable interface method.
func (fn *evalVarArgs) ID() int64 {
	return fn.id
}

// Eval implements the Interpretable interface method.
func (fn *evalVarArgs) Eval(ctx Activation) ref.Value {
	argVals := make([]ref.Value, len(fn.args), len(fn.args))
	// Early return if any argument to the function is unknown or error.
	for i, arg := range fn.args {
		argVals[i] = arg.Eval(ctx)
		if types.IsUnknownOrError(argVals[i]) {
			return argVals[i]
		}
	}
	// If the implementation is bound and the argument value has the right traits required to
	// invoke it, then call the implementation.
	arg0 := argVals[0]
	if fn.impl != nil && (fn.trait == 0 || arg0.Type().HasTrait(fn.trait)) {
		return fn.impl(argVals...)
	}
	// Otherwise, if the argument is a ReceiverType attempt to invoke the receiver method on the
	// operand (arg0).
	if arg0.Type().HasTrait(traits.ReceiverType) {
		return arg0.(traits.Receiver).Receive(fn.function, fn.overload, argVals[1:])
	}
	return types.NewErr("no such overload: %s", fn.function)
}

type evalList struct {
	id    int64
	elems []Interpretable
}

// ID implements the Interpretable interface method.
func (l *evalList) ID() int64 {
	return l.id
}

// Eval implements the Interpretable interface method.
func (l *evalList) Eval(ctx Activation) ref.Value {
	elemVals := make([]ref.Value, len(l.elems), len(l.elems))
	// If any argument is unknown or error early terminate.
	for i, elem := range l.elems {
		elemVal := elem.Eval(ctx)
		if types.IsUnknownOrError(elemVal) {
			return elemVal
		}
		elemVals[i] = elemVal
	}
	return types.NewDynamicList(elemVals)
}

type evalMap struct {
	id   int64
	keys []Interpretable
	vals []Interpretable
}

// ID implements the Interpretable interface method.
func (m *evalMap) ID() int64 {
	return m.id
}

// Eval implements the Interpretable interface method.
func (m *evalMap) Eval(ctx Activation) ref.Value {
	entries := make(map[ref.Value]ref.Value)
	// If any argument is unknown or error early terminate.
	for i, key := range m.keys {
		keyVal := key.Eval(ctx)
		if types.IsUnknownOrError(keyVal) {
			return keyVal
		}
		valVal := m.vals[i].Eval(ctx)
		if types.IsUnknownOrError(valVal) {
			return valVal
		}
		entries[keyVal] = valVal
	}
	return types.NewDynamicMap(entries)
}

type evalObj struct {
	id       int64
	typeName string
	fields   []string
	vals     []Interpretable
	types    ref.TypeProvider
}

// ID implements the Interpretable interface method.
func (o *evalObj) ID() int64 {
	return o.id
}

// Eval implements the Interpretable interface method.
func (o *evalObj) Eval(ctx Activation) ref.Value {
	fieldVals := make(map[string]ref.Value)
	// If any argument is unknown or error early terminate.
	for i, field := range o.fields {
		val := o.vals[i].Eval(ctx)
		if types.IsUnknownOrError(val) {
			return val
		}
		fieldVals[field] = val
	}
	return o.types.NewValue(o.typeName, fieldVals)
}

type evalFold struct {
	id        int64
	accuVar   string
	iterVar   string
	iterRange Interpretable
	accu      Interpretable
	cond      Interpretable
	step      Interpretable
	result    Interpretable
}

// ID implements the Interpretable interface method.
func (fold *evalFold) ID() int64 {
	return fold.id
}

// Eval implements the Interpretable interface method.
func (fold *evalFold) Eval(ctx Activation) ref.Value {
	foldRange := fold.iterRange.Eval(ctx)
	if !foldRange.Type().HasTrait(traits.IterableType) {
		return types.ValOrErr(foldRange, "got '%T', expected iterable type", foldRange)
	}
	// Configure the fold activation with the accumulator initial value.
	accuCtx := varActivationPool.Get().(*varActivation)
	accuCtx.parent = ctx
	accuCtx.name = fold.accuVar
	accuCtx.val = fold.accu.Eval(ctx)
	iterCtx := varActivationPool.Get().(*varActivation)
	iterCtx.parent = accuCtx
	iterCtx.name = fold.iterVar
	it := foldRange.(traits.Iterable).Iterator()
	for it.HasNext() == types.True {
		// Modify the iter var in the fold activation.
		iterCtx.val = it.Next()

		// Evaluate the condition, terminate the loop if false.
		cond := fold.cond.Eval(iterCtx)
		condBool, ok := cond.(types.Bool)
		if !types.IsUnknown(cond) && ok && condBool != types.True {
			break
		}

		// Evalute the evaluation step into accu var.
		accuCtx.val = fold.step.Eval(iterCtx)
	}
	// Compute the result.
	res := fold.result.Eval(accuCtx)
	varActivationPool.Put(iterCtx)
	varActivationPool.Put(accuCtx)
	return res
}
