// Code generated by go-bindata. DO NOT EDIT.
// sources:
// templates/config.html (3.793kB)

package assets

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type asset struct {
	bytes  []byte
	info   os.FileInfo
	digest [sha256.Size]byte
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _templatesConfigHtml = []byte(`{{ define "content" }}

    <p>
        The Mesh Configuration Protocol (MCP) client state for this process.
    </p>

    <style>
    .metadata-table-cell {
        margin: 0;
        padding: 0;
    }

    .metadata-table {
        margin: 0;
        padding: 0;
    }
    </style>

    <div>
        <table>
            <thead>
            <tr>
                <th colspan="2">Client Info</th>
            </tr>
            </thead>
            <tbody>
            <tr>
                <td>ID</td>
                <td>{{.ID}}</td>
            </tr>
            <tr>
                <td>Metadata</td>
                <td class="metadata-table-cell">
                    <table class="metadata-table">
                    {{ range $key, $value := .Metadata }}
                    <tr>
                        <td>{{$key}}</td>
                        <td>{{$value}}</td>
                    {{end}}
                    </table>
                </td>
            </tr>
            </tbody>
        </table>
    </div>

    <div>
        <table>
            <thead>
            <tr>
                <th>Supported Collections</th>
            </tr>
            </thead>
            <tbody>
            {{ range $value := .Collections }}
            <tr>
                <td>{{$value}}</td>
            {{end}}
            </tbody>
        </table>
    </div>

    <div>
        <table id="recent-requests-table">
            <thead>
            <tr>
                <th colspan="4">Recent Requests</th>
            </tr>
            <tr>
                <th>Time</th>
                <th>Collection</th>
                <th>Acked</th>
                <th>Nonce</th>
            </tr>
            </thead>

            <tbody>

            </tbody>
        </table>
    </div>
{{ template "last-refresh" .}}

<script>
    "use strict";

    function refreshRecentRequests() {
        var url = window.location.protocol + "//" + window.location.host + "/configj/";

        var ajax = new XMLHttpRequest();
        ajax.onload = onload;
        ajax.onerror = onerror;
        ajax.open("GET", url, true);
        ajax.send();

        function onload() {
            if (this.status == 200) { // request succeeded
                var data = JSON.parse(this.responseText);

                var table = document.getElementById("recent-requests-table");

                var tbody = document.createElement("tbody");
                for (var i = 0; i < data.LatestRequests.length; i++) {
                    var row = document.createElement("tr");

                    var c1 = document.createElement("td");
                    c1.innerText = data.LatestRequests[i].Time;
                    row.appendChild(c1);

                    var c2 = document.createElement("td");
                    c2.innerText = data.LatestRequests[i].Request.Collection;
                    row.appendChild(c2);


                    var c3 = document.createElement("td");
                    if (data.LatestRequests[i].Request.ErrorDetail === null) {
                        c3.innerText = "true"
                    } else {
                        c3.innerText = "false"
                    }
                    row.appendChild(c3);

                    var c4 = document.createElement("td");
                    c4.innerText = data.LatestRequests[i].Request.ResponseNonce;
                    row.appendChild(c4);

                    tbody.appendChild(row)
                }
                table.removeChild(table.tBodies[0]);
                table.appendChild(tbody);

                updateRefreshTime();
            }
        }

        function onerror(e) {
            console.error(e);
        }
    }

    refreshRecentRequests();
    window.setInterval(refreshRecentRequests, 1000);

</script>

{{ end }}
`)

func templatesConfigHtmlBytes() ([]byte, error) {
	return _templatesConfigHtml, nil
}

func templatesConfigHtml() (*asset, error) {
	bytes, err := templatesConfigHtmlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "templates/config.html", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x2a, 0xec, 0xc8, 0xe2, 0xec, 0x53, 0x71, 0xfc, 0xd5, 0xb2, 0x4d, 0x2d, 0xfc, 0x8b, 0xba, 0x53, 0xb9, 0x51, 0x7, 0x29, 0x8b, 0x6, 0x2e, 0xcb, 0x4a, 0xcc, 0xd4, 0x1b, 0x4a, 0x6d, 0x58, 0x1}}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// AssetString returns the asset contents as a string (instead of a []byte).
func AssetString(name string) (string, error) {
	data, err := Asset(name)
	return string(data), err
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// MustAssetString is like AssetString but panics when Asset would return an
// error. It simplifies safe initialization of global variables.
func MustAssetString(name string) string {
	return string(MustAsset(name))
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetDigest returns the digest of the file with the given name. It returns an
// error if the asset could not be found or the digest could not be loaded.
func AssetDigest(name string) ([sha256.Size]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s can't read by error: %v", name, err)
		}
		return a.digest, nil
	}
	return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s not found", name)
}

// Digests returns a map of all known files and their checksums.
func Digests() (map[string][sha256.Size]byte, error) {
	mp := make(map[string][sha256.Size]byte, len(_bindata))
	for name := range _bindata {
		a, err := _bindata[name]()
		if err != nil {
			return nil, err
		}
		mp[name] = a.digest
	}
	return mp, nil
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"templates/config.html": templatesConfigHtml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"},
// AssetDir("data/img") would return []string{"a.png", "b.png"},
// AssetDir("foo.txt") and AssetDir("notexist") would return an error, and
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		canonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(canonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"templates": &bintree{nil, map[string]*bintree{
		"config.html": &bintree{templatesConfigHtml, map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory.
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	return os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
}

// RestoreAssets restores an asset under the given directory recursively.
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(canonicalName, "/")...)...)
}
