// Copyright 2016 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package template

// BootstrapTemplate defines the template used to generate code that glues Mixer with generated template interfaces.
// nolint:lll
var BootstrapTemplate = `// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
 
// THIS FILE IS AUTOMATICALLY GENERATED.
 
package {{.PkgName}}
 
import (
    "github.com/gogo/protobuf/proto"
    "fmt"
    "context"
    "strings"
    "net"
    "istio.io/istio/mixer/pkg/adapter"
    "istio.io/istio/mixer/pkg/attribute"
    "istio.io/istio/mixer/pkg/lang/ast"
    "istio.io/istio/mixer/pkg/lang/compiled"
    "istio.io/istio/pkg/log"
    "istio.io/istio/mixer/pkg/template"
    istio_adapter_model_v1beta1 "istio.io/api/mixer/adapter/model/v1beta1"
    istio_policy_v1beta1 "istio.io/api/policy/v1beta1"
    {{range .TemplateModels}}
        "{{.PackageImportPath}}"
    {{end}}
    $$additional_imports$$
)
 
// Add void usages for some imports so that go linter does not complain in case the imports does not get used in the
// below codegen.
var (
    _ net.IP
    _ istio_policy_v1beta1.AttributeManifest
    _ = strings.Reader{}
)
 
type (
    getFn         func(name string) (value interface{}, found bool)
    namesFn       func() []string
    doneFn        func()
    debugStringFn func() string
    wrapperAttr struct {
        get         getFn
        names       namesFn
        done        doneFn
        debugString debugStringFn
    }
)
 
func newWrapperAttrBag(get getFn, names namesFn, done doneFn, debugString debugStringFn) attribute.Bag {
    return &wrapperAttr{
        debugString: debugString,
        done:        done,
        get:         get,
        names:       names,
    }
}
 
// Get returns an attribute value.
func (w *wrapperAttr) Get(name string) (value interface{}, found bool) {
    return w.get(name)
}

// Contains returns true if key is present.
func (w *wrapperAttr) Contains(key string) (found bool) {
    _, found = w.get(key)
    return found
}
 
// Names returns the names of all the attributes known to this bag.
func (w *wrapperAttr) Names() []string {
    return w.names()
}
 
// Done indicates the bag can be reclaimed.
func (w *wrapperAttr) Done() {
    w.done()
}
 
// String provides a dump of an attribute Bag that avoids affecting the
// calculation of referenced attributes.
func (w *wrapperAttr) String() string {
    return w.debugString()
}
 
var (
    SupportedTmplInfo = map[string]template.Info {
    {{range .TemplateModels}}
        {{.GoPackageName}}.TemplateName: {
            Name: {{.GoPackageName}}.TemplateName,
            Impl: "{{.PackageName}}",
            CtrCfg:  &{{.GoPackageName}}.InstanceParam{},
            Variety:   istio_adapter_model_v1beta1.{{.VarietyName}},
            BldrInterfaceName:  {{.GoPackageName}}.TemplateName + "." + "HandlerBuilder",
            HndlrInterfaceName: {{.GoPackageName}}.TemplateName + "." + "Handler",
            BuilderSupportsTemplate: func(hndlrBuilder adapter.HandlerBuilder) bool {
                _, ok := hndlrBuilder.({{.GoPackageName}}.HandlerBuilder)
                return ok
            },
            HandlerSupportsTemplate: func(hndlr adapter.Handler) bool {
                _, ok := hndlr.({{.GoPackageName}}.Handler)
                return ok
            },
            InferType: func(cp proto.Message, tEvalFn template.TypeEvalFn) (proto.Message, error) {
                {{$goPkgName := .GoPackageName}}
                {{$varietyName := .VarietyName}}
                {{range getAllMsgs .}}
                {{with $msg := .}}
 
                {{if ne $varietyName "TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR"}}
                var {{getBuildFnName $msg.Name}} func(param *{{$goPkgName}}.{{getResourcMessageInterfaceParamTypeName $msg.Name}},
                    path string) (*{{$goPkgName}}.{{getResourcMessageTypeName $msg.Name}}, error)
                {{else}}
                var {{getBuildFnName $msg.Name}} func(param *{{$goPkgName}}.{{getResourcMessageInterfaceParamTypeName $msg.Name}},
                    path string) (proto.Message, error)
                {{end}}
                _ = {{getBuildFnName $msg.Name}}
                {{end}}
                {{end}}
                {{range getAllMsgs .}}
                {{with $msg := .}}
 
                {{if ne $varietyName "TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR"}}
                {{getBuildFnName $msg.Name}} = func(param *{{$goPkgName}}.{{getResourcMessageInterfaceParamTypeName $msg.Name}},
                    path string) (*{{$goPkgName}}.{{getResourcMessageTypeName $msg.Name}}, error) {
                {{else}}
                {{getBuildFnName $msg.Name}} = func(param *{{$goPkgName}}.{{getResourcMessageInterfaceParamTypeName $msg.Name}},
                    path string) (proto.Message, error) {
                {{end}}
 
                if param == nil {
                    return nil, nil
                }
                {{if ne $varietyName "TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR"}}
                infrdType := &{{$goPkgName}}.{{getResourcMessageTypeName $msg.Name}}{}
                {{end}}
                var err error = nil
 
                {{range $msg.Fields}}
                    {{if containsValueTypeOrResMsg .GoType}}
                        {{if ne $varietyName "TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR"}}
                        {{if .GoType.IsMap}}
                            {{$typeName := getTypeName .GoType.MapValue}}
                            {{if .GoType.MapValue.IsResourceMessage}}
                                infrdType.{{.GoName}} = make(map[{{.GoType.MapKey.Name}}]*{{$goPkgName}}.{{getResourcMessageTypeName $typeName}}, len(param.{{.GoName}}))
                            {{else}}
                                infrdType.{{.GoName}} = make(map[{{.GoType.MapKey.Name}}]istio_policy_v1beta1.ValueType, len(param.{{.GoName}}))
                            {{end}}
                            for k, v := range param.{{.GoName}} {
                            {{if .GoType.MapValue.IsResourceMessage}}
                                if infrdType.{{.GoName}}[k], err = {{getBuildFnName $typeName}}(v, path + "{{.GoName}}[" + k + "]."); err != nil {
                            {{else}}
                                if infrdType.{{.GoName}}[k], err = tEvalFn(v); err != nil {
                            {{end}}
                                    return nil, fmt.Errorf("failed to evaluate expression for field '%s%s[%s]'; %v", path,"{{.GoName}}", k, err)
                                }
                            }
                        {{else}}
                            {{if .GoType.IsResourceMessage}}
                                if param.{{.GoName}} != nil {
                                    {{$typeName := getTypeName .GoType}}
                                    if infrdType.{{.GoName}}, err = {{getBuildFnName $typeName}}(param.{{.GoName}}, path + "{{.GoName}}."); err != nil {
                                        return nil, fmt.Errorf("failed to evaluate expression for field '%s'; %v", path + "{{.GoName}}", err)
                                    }
                                }
                            {{else}}
                                if param.{{.GoName}} == "" {
                                    infrdType.{{.GoName}} = {{getUnspecifiedValueType}}
                                } else if infrdType.{{.GoName}}, err = tEvalFn(param.{{.GoName}}); err != nil {
                                    return nil, fmt.Errorf("failed to evaluate expression for field '%s'; %v", path + "{{.GoName}}", err)
                                }
                            {{end}}
                        {{end}}
                        {{end}}
                    {{else}}
                        {{if .GoType.IsMap}}
                            for k, v := range param.{{.GoName}} {
                                if t, e := tEvalFn(v); e != nil || t != {{getValueType .GoType.MapValue}} {
                                    if e != nil {
                                        return nil, fmt.Errorf("failed to evaluate expression for field '%s%s[%s]'; %v", path, "{{.GoName}}", k, e)
                                    }
                                    return nil, fmt.Errorf(
                                        "error type checking for field '%s%s[%s]': Evaluated expression type %v want %v", path, "{{.GoName}}", k, t, {{getValueType .GoType.MapValue}})
                                }
                            }
                        {{else}}
                            if param.{{.GoName}} != "" {
                                if t, e := tEvalFn(param.{{.GoName}}); e != nil || t != {{getValueType .GoType}} {
                                    if e != nil {
                                        return nil, fmt.Errorf("failed to evaluate expression for field '%s': %v", path + "{{.GoName}}", e)
                                    }
                                    return nil, fmt.Errorf("error type checking for field '%s': Evaluated expression type %v want %v", path + "{{.GoName}}", t, {{getValueType .GoType}})
                                }
                            }
                        {{end}}
                    {{end}}
                {{end}}
                {{if ne $varietyName "TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR"}}
                return infrdType, err
                {{else}}
                return nil, err
                {{end}}
                }
                {{end}}
                {{end}}
 
                instParam := cp.(*{{.GoPackageName}}.InstanceParam)
                {{if eq $varietyName "TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR"}}
                const fullOutName = "{{.GoPackageName}}.output."
                for attr, exp := range instParam.AttributeBindings {
                    expr := strings.Replace(exp, "$out.", fullOutName, -1)
                    t1, err := tEvalFn(expr)
                    if err != nil {
                        return nil, fmt.Errorf("error evaluating AttributeBinding expression '%s' for attribute '%s': %v", expr, attr, err)
                    }
                    t2, err := tEvalFn(attr)
                    if err != nil {
                        return nil, fmt.Errorf("error evaluating AttributeBinding expression for attribute key '%s': %v", attr, err)
                    }
                    if t1 != t2 {
                        return nil, fmt.Errorf(
                        "error evaluating AttributeBinding: type '%v' for attribute '%s' does not match type '%s' for expression '%s'",
                            t2, attr, t1, expr)
                    }
                }
                {{end}}
                return BuildTemplate(instParam, "")
            },
            {{if ne $varietyName "TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR"}}
            SetType: func(types map[string]proto.Message, builder adapter.HandlerBuilder) {
                // Mixer framework should have ensured the type safety.
                castedBuilder := builder.({{.GoPackageName}}.HandlerBuilder)
                castedTypes := make(map[string]*{{.GoPackageName}}.Type, len(types))
                for k, v := range types {
                    // Mixer framework should have ensured the type safety.
                    v1 := v.(*{{.GoPackageName}}.Type)
                    castedTypes[k] = v1
                }
                castedBuilder.Set{{.InterfaceName}}Types(castedTypes)
            },
            {{end}}

            {{if eq $varietyName "TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR"}}
            {{$goPkgName := .GoPackageName}}
            AttributeManifests: []*istio_policy_v1beta1.AttributeManifest{
                {
                    Attributes: map[string]*istio_policy_v1beta1.AttributeManifest_AttributeInfo{
                        {{range .OutputTemplateMessage.Fields}}
                        "{{$goPkgName}}.output.{{.ProtoName}}": {
                            ValueType: {{getValueType .GoType}},
                        },
                        {{end}}
                    },
                },
            },
            {{end}}

        {{if eq .VarietyName "TEMPLATE_VARIETY_REPORT"}}
        // DispatchReport dispatches the instances to the handler.
        DispatchReport: func(ctx context.Context, handler adapter.Handler, inst []interface{}) error {

            // Convert the instances from the generic []interface{}, to their specialized type.
            instances := make([]*{{.GoPackageName}}.Instance, len(inst))
            for i, instance := range inst {
                instances[i] = instance.(*{{.GoPackageName}}.Instance)
            }

            // Invoke the handler.
            if err := handler.({{.GoPackageName}}.Handler).Handle{{.InterfaceName}}(ctx, instances); err != nil {
                return fmt.Errorf("failed to report all values: %v", err)
            }
            return nil
        },
        {{end}}
 
        {{if eq .VarietyName "TEMPLATE_VARIETY_CHECK"}}
        // DispatchCheck dispatches the instance to the handler.
        DispatchCheck: func(ctx context.Context, handler adapter.Handler, inst interface{}, out *attribute.MutableBag, outPrefix string) (adapter.CheckResult, error) {

            // Convert the instance from the generic interface{}, to its specialized type.
            instance := inst.(*{{.GoPackageName}}.Instance)

            // Invoke the handler.
            return handler.({{.GoPackageName}}.Handler).Handle{{.InterfaceName}}(ctx, instance)
        },
        {{end}}

        {{if eq .VarietyName "TEMPLATE_VARIETY_CHECK_WITH_OUTPUT"}}
        // DispatchCheck dispatches the instance to the handler.
        DispatchCheck: func(ctx context.Context, handler adapter.Handler, inst interface{}, out *attribute.MutableBag, outPrefix string) (adapter.CheckResult, error) {

            // Convert the instance from the generic interface{}, to its specialized type.
            instance := inst.(*{{.GoPackageName}}.Instance)

            // Invoke the handler.
            res, obj, err := handler.({{.GoPackageName}}.Handler).Handle{{.InterfaceName}}(ctx, instance)

            if out != nil {
              {{range .OutputTemplateMessage.Fields}}
              out.Set(outPrefix + "{{.ProtoName}}", obj.{{.GoName}})
              {{end}}
            }
            return res, err
        },

        AttributeManifests: []*istio_policy_v1beta1.AttributeManifest{
            {
                Attributes: map[string]*istio_policy_v1beta1.AttributeManifest_AttributeInfo{
                    {{range .OutputTemplateMessage.Fields}}
                    "{{.ProtoName}}": {
                        ValueType: {{getValueType .GoType}},
                    },
                    {{end}}
                },
            },
        },
        {{end}}

        {{if eq .VarietyName "TEMPLATE_VARIETY_QUOTA"}}
        // DispatchQuota dispatches the instance to the handler.
        DispatchQuota: func(ctx context.Context, handler adapter.Handler, inst interface{}, args adapter.QuotaArgs) (adapter.QuotaResult, error) {

            // Convert the instance from the generic interface{}, to its specialized type.
            instance := inst.(*{{.GoPackageName}}.Instance)
 
            // Invoke the handler.
            return handler.({{.GoPackageName}}.Handler).Handle{{.InterfaceName}}(ctx, instance, args)
        },
        {{end}}
 
        {{if eq .VarietyName "TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR"}}
        // DispathGenAttrs dispatches the instance to the attribute producing handler.
        DispatchGenAttrs: func(ctx context.Context, handler adapter.Handler, inst interface{}, attrs attribute.Bag,
            mapper template.OutputMapperFn) (*attribute.MutableBag, error) {
 
            // Convert the instance from the generic interface{}, to their specialized type.
            instance := inst.(*{{.GoPackageName}}.Instance)
 
            // Invoke the handler.
            out, err := handler.({{.GoPackageName}}.Handler).Generate{{.InterfaceName}}Attributes(ctx, instance)
            if err != nil {
                return nil, err
            }

            // Construct a wrapper bag around the returned output message and pass it to the output mapper
            // to map $out values back to the destination attributes in the ambient context.
            const fullOutName = "{{.GoPackageName}}.output."
            outBag := newWrapperAttrBag(
                func(name string) (value interface{}, found bool) {
                    field := strings.TrimPrefix(name, fullOutName)
                    if len(field) != len(name) {
                        if !out.WasSet(field) {
                           return nil, false
                        }
                        switch field {
                            {{range .OutputTemplateMessage.Fields}}
                            case "{{.ProtoName}}":
                                {{if isAliasType .GoType.Name}}
                                return {{getAliasType .GoType.Name}}(out.{{.GoName}}), true
                                {{else}}
                                return out.{{.GoName}}, true
                                {{end}}
                            {{end}}
                            default:
                            return nil, false
                        }
                    }
                    return attrs.Get(name)
                },
                func() []string {return attrs.Names()},
                func() {attrs.Done()},
                func() string {return attrs.String()},
            )

            // Mapper will map back $out values in the outBag into ambient attribute names, and return
            // a bag with these additional attributes.
            return mapper(outBag)
        },
        {{end}}

        // CreateInstanceBuilder creates a new template.InstanceBuilderFN based on the supplied instance parameters. It uses
        // the expression builder to create a new instance of a builder struct for the instance type. Created
        // InstanceBuilderFn closes over this struct. When InstanceBuilderFn is called it, in turn, calls into
        // the builder with an attribute bag.
        //
        // See template.CreateInstanceBuilderFn for more details.
        CreateInstanceBuilder: func(instanceName string, param proto.Message, expb *compiled.ExpressionBuilder) (template.InstanceBuilderFn, error) {
            {{$t := .}}
            {{$m := $t.TemplateMessage}}
            {{$newBuilderFnName := getNewMessageBuilderFnName $t $m}}

            // If the parameter is nil. Simply return nil. The builder, then, will also return nil.
            if param == nil {
                return func(attr attribute.Bag) (interface{}, error) {
                    return nil, nil
                }, nil
            }

            // Instantiate a new builder for the instance.
            builder, errp := {{$newBuilderFnName}}(expb, param.(*{{$t.GoPackageName}}.{{getResourcMessageInterfaceParamTypeName $m.Name}}))
            if !errp.IsNil() {
              return nil, errp.AsCompilationError(instanceName)
            }
 
            return func(attr attribute.Bag) (interface{}, error) {
                // Use the instantiated builder (that this fn closes over) to construct an instance.
                e, errp := builder.build(attr)
                if !errp.IsNil() {
                    err := errp.AsEvaluationError(instanceName)
                    log.Error(err.Error())
                    return nil, err
                }
 
                e.Name = instanceName
                return e, nil
            }, nil
        },
 
        {{if eq .VarietyName "TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR"}}
        // CreateOutputExpressions creates a set of compiled expressions based on the supplied instance parameters.
        //
        // See template.CreateOutputExpressionsFn for more details.
        CreateOutputExpressions: func(
            instanceParam proto.Message,
            finder ast.AttributeDescriptorFinder,
            expb *compiled.ExpressionBuilder) (map[string]compiled.Expression, error) {
            var err error
            var expType istio_policy_v1beta1.ValueType

            // Convert the generic instanceParam to its specialized type.
            param := instanceParam.(*{{$t.GoPackageName}}.{{getResourcMessageInterfaceParamTypeName $m.Name}})

            // Create a mapping of expressions back to the attribute names.
            expressions := make(map[string]compiled.Expression, len(param.AttributeBindings))

            const fullOutName = "{{.GoPackageName}}.output."
            for attrName, outExpr := range param.AttributeBindings {
                attrInfo := finder.GetAttribute(attrName)
                if attrInfo == nil {
                    log.Warnf("attribute not found when mapping outputs: attr='%s', expr='%s'", attrName, outExpr)
                    continue
                }

                ex := strings.Replace(outExpr, "$out.", fullOutName, -1)

                if expressions[attrName], expType, err = expb.Compile(ex); err != nil {
                    return nil, err
                }

                if attrInfo.ValueType != expType {
                    log.Warnf("attribute type mismatch: attr='%s', attrType='%v', expr='%s', exprType='%v'", attrName, attrInfo.ValueType, outExpr, expType)
                    continue
                }
            }

            return expressions, nil
        },
        {{end}}
 
        },
    {{end}}
    }
)

// Builders for all known message types.
{{range .TemplateModels}}
    {{$t := .}} {{/* t := template */}}

    {{range getAllMsgs $t}}
        {{$m := . }} {{/* m := message */}}
        {{$builderName      := getMessageBuilderName $t $m}}
        {{$newBuilderFnName := getNewMessageBuilderFnName $t $m}}

        // builder struct for constructing an instance of {{$m.Name}}.
        type {{$builderName}} struct {

        {{range $m.Fields}}
            {{$f := .}}  {{/* f := field */}}

            // builder for field {{$f.ProtoName}}: {{$f.GoType.Name}}.
            {{if $f.GoType.IsMap}}
                {{if $f.GoType.MapValue.IsResourceMessage}}
                    {{/* Map of fieldName => builder for maps with sub-message value types */}}
                    {{builderFieldName $f}} map[string]*{{getMessageBuilderName $t $f.GoType.MapValue}}
                {{else}}
                    {{/* Map of fieldName => expression for map[string]<simple-type> fields. */}}
                    {{builderFieldName $f}} map[string]compiled.Expression
                {{end}}
            {{else}}
                {{if $f.GoType.IsResourceMessage}}
                    {{/* Auto-generated builder for sub-message field types. */}}
                    {{builderFieldName $f}}  *{{getMessageBuilderName $t $f.GoType}}
                {{else}}
                    {{/* compiled.Expression for fields of basic type. */}}
                    {{builderFieldName $f}}  compiled.Expression
                {{end}}
            {{end}}
        {{end}}

        } // {{$builderName}}
 
 
        // Instantiates and returns a new builder for {{$m.Name}}, based on the provided instance parameter.
        func {{$newBuilderFnName}}(
            expb *compiled.ExpressionBuilder,
            param *{{$t.GoPackageName}}.{{getResourcMessageInterfaceParamTypeName $m.Name}}) (*{{$builderName}}, template.ErrorPath) {

            // If the parameter is nil. Simply return nil. The builder, then, will also return nil.
            if param == nil {
                return nil, template.ErrorPath{}
            }

            b := &{{$builderName}} {}
 
            var exp compiled.Expression
            _ = exp
            var err error
            _ = err
            var errp template.ErrorPath
            _ = errp
            var expType istio_policy_v1beta1.ValueType
            _ = expType

            {{range $m.Fields}}
                {{$f := .}} {{/* f := field */}}
 
                {{if $f.GoType.IsMap}}
                    {{if $f.GoType.MapValue.IsResourceMessage}}
                        {{/* Construct the map of fieldName => builder for maps with sub-message value types */}}
                        b.{{builderFieldName $f}} = make(map[string]*{{getMessageBuilderName $t $f.GoType.MapValue}}, len(param.{{$f.GoName}}))
                        for k, v := range param.{{$f.GoName}} {
                            var vb *{{getMessageBuilderName $t $f.GoType.MapValue}}
                            if vb, errp = {{getNewMessageBuilderFnName $t $f.GoType.MapValue}}(expb, v); !errp.IsNil() {
                                return nil, errp.WithPrefix("{{$f.GoName}}["+ k + "]")
                            }
                            b.{{builderFieldName $f}}[k] = vb
                        }
                    {{else}}
                        {{/* Construct the map of fieldName => expression for map[string]<simple-type> fields. */}}
                        b.{{builderFieldName $f}} = make(map[string]compiled.Expression, len(param.{{$f.GoName}}))
                        for k, v := range param.{{$f.GoName}} {
                            var exp compiled.Expression
                            if exp, expType, err = expb.Compile(v); err != nil {
                                return nil, template.NewErrorPath("{{$f.GoName}}["+ k + "]", err)
                            }
                            {{if isPrimitiveType $f.GoType.MapValue}}
                                if expType != {{getValueType $f.GoType.MapValue}} {
                                    err = fmt.Errorf("instance field type mismatch: expected='%v', actual='%v', expression='%s'", {{getValueType $f.GoType.MapValue}}, expType, v)
                                    return nil, template.NewErrorPath("{{$f.GoName}}[" + k + "]", err)
                                }
                            {{end}}

                            b.{{builderFieldName $f}}[k] = exp
                        }
                    {{end}}
                {{else}}
                    {{if $f.GoType.IsResourceMessage}}
                        {{/* Construct the builder instance for sub-message field types. */}}
                        if b.{{builderFieldName $f}}, errp = {{getNewMessageBuilderFnName $t $f.GoType}}(expb, param.{{$f.GoName}}); !errp.IsNil() {
                            return nil, errp.WithPrefix("{{$f.GoName}}")
                        }
                    {{else}}
                        {{/* Construct the compiled.Expression for fields of basic type. */}}
                        if param.{{$f.GoName}} == "" {
                            b.{{builderFieldName $f}} = nil
                        } else {
                            b.{{builderFieldName $f}}, expType, err = expb.Compile(param.{{$f.GoName}})
                            if err != nil {
                                return nil, template.NewErrorPath("{{$f.GoName}}", err)
                            }
                            {{if isPrimitiveType $f.GoType}}
                                if expType != {{getValueType $f.GoType}} {
                                    err = fmt.Errorf("instance field type mismatch: expected='%v', actual='%v', expression='%s'", {{getValueType $f.GoType}}, expType, param.{{$f.GoName}})
                                    return nil, template.NewErrorPath("{{$f.GoName}}", err)
                                }
                            {{end}}
                        }
                    {{end}}
                {{end}}
 
            {{end}}
 
            return b, template.ErrorPath{}
        }
 
        // build and return the instance, given a set of attributes.
        func (b *{{$builderName}}) build(
            attrs attribute.Bag) (*{{$t.GoPackageName}}.{{getResourcMessageInstanceName $m.Name}}, template.ErrorPath) {
 
            if b == nil {
                return nil, template.ErrorPath{}
            }
 
            var err error
            _ = err
            var errp template.ErrorPath
            _ = errp
            var vBool bool
            _ = vBool
            var vInt int64
            _ = vInt
            var vString string
            _ = vString
            var vDouble float64
            _ = vDouble
            var vIface interface{}
            _ = vIface

            r := &{{$t.GoPackageName}}.{{getResourcMessageInstanceName $m.Name}}{}
            {{range $m.Fields}}
                {{$f := .}}
 
                {{if $f.GoType.IsMap}}
                    {{if $f.GoType.MapValue.IsResourceMessage}}

                        r.{{$f.GoName}} = make(map[string]*{{$t.GoPackageName}}.{{getTypeName .GoType.MapValue}}, len(b.{{builderFieldName $f}}))
                        for k, v := range b.{{builderFieldName $f}} {
                            if r.{{$f.GoName}}[k], errp = v.build(attrs); !errp.IsNil() {
                                return nil, errp.WithPrefix("{{$f.GoName}}["+ k + "]")
                            }
                        }
                    {{else}}
                        {{if containsValueTypeOrResMsg $f.GoType.MapValue}}
                            r.{{$f.GoName}} = make(map[{{$f.GoType.MapKey.Name}}]interface{}, len(b.{{builderFieldName $f}}))
                        {{else}}
                            r.{{$f.GoName}} = make(map[{{$f.GoType.MapKey.Name}}]{{$f.GoType.MapValue.Name}}, len(b.{{builderFieldName $f}}))
                        {{end}}
                        for k, v := range b.{{builderFieldName $f}} {
                            {{if isPrimitiveType $f.GoType.MapValue}}
                                {{getLocalVar $f.GoType.MapValue}}, err = v.{{getEvalMethod $f.GoType.MapValue}}(attrs)
                                if err != nil {
                                    return nil, template.NewErrorPath("{{$f.GoName}}["+ k + "]", err)
                                }
                                r.{{$f.GoName}}[k] = {{getLocalVar $f.GoType.MapValue}}
                            {{else}}
                                if {{getLocalVar $f.GoType.MapValue}}, err = v.{{getEvalMethod $f.GoType.MapValue}}(attrs); err != nil {
                                    return nil, template.NewErrorPath("{{$f.GoName}}["+ k + "]", err)
                                }
                                {{if containsValueTypeOrResMsg $f.GoType.MapValue}}
                                    r.{{$f.GoName}}[k] = {{getLocalVar $f.GoType.MapValue}}
                                {{else}}
                                    {{if isAliasTypeSkipIp $f.GoType.MapValue.Name}}
                                        r.{{$f.GoName}}[k] = {{$f.GoType.MapValue.Name}}({{getLocalVar $f.GoType.MapValue}}.({{getAliasType $f.GoType.MapValue.Name}}))
                                    {{else}}
                                        r.{{$f.GoName}}[k] = {{getLocalVar $f.GoType.MapValue}}.({{$f.GoType.MapValue.Name}}) {{reportTypeUsed $f.GoType.MapValue}}
                                    {{end}}
                                {{end}}
                            {{end}}
                        }
                    {{end}}
                {{else}}
                    if b.{{builderFieldName $f}} != nil {
                    {{if $f.GoType.IsResourceMessage}}
                            if r.{{$f.GoName}}, errp = b.{{builderFieldName $f}}.build(attrs); !errp.IsNil() {
                            return nil, errp.WithPrefix("{{$f.GoName}}")
                        }
                    {{else}}
                        {{if isPrimitiveType $f.GoType}}
                            {{getLocalVar $f.GoType}}, err = b.{{builderFieldName $f}}.{{getEvalMethod $f.GoType}}(attrs)
                            if err != nil {
                                return nil, template.NewErrorPath("{{$f.GoName}}", err)
                            }
                            r.{{$f.GoName}} = {{getLocalVar $f.GoType}}
                        {{else}}
                            if vIface, err = b.{{builderFieldName $f}}.{{getEvalMethod $f.GoType}}(attrs); err != nil {
                                return nil, template.NewErrorPath("{{$f.GoName}}", err)
                            }
                            {{if containsValueTypeOrResMsg $f.GoType}}
                                r.{{$f.GoName}} = vIface
                            {{else}}
                                {{if isAliasTypeSkipIp $f.GoType.Name}}
                                    r.{{$f.GoName}} = {{$f.GoType.Name}}(vIface.({{getAliasType .GoType.Name}}))
                                {{else}}
                                    r.{{$f.GoName}} = vIface.({{$f.GoType.Name}}) {{reportTypeUsed $f.GoType}}
                                {{end}}
                            {{end}}
                        {{end}}
                    {{end}}
                    }
                {{end}}
            {{end}}
 
            return r, template.ErrorPath{}
        }
 
    {{end}}
{{end}}
 
`
