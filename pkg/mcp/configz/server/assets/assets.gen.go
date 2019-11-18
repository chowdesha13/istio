// Code generated by go-bindata. DO NOT EDIT.
// sources:
// templates/config.html

package assets


import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)


type asset struct {
	bytes []byte
	info  fileInfoEx
}

type fileInfoEx interface {
	os.FileInfo
	MD5Checksum() string
}

type bindataFileInfo struct {
	name        string
	size        int64
	mode        os.FileMode
	modTime     time.Time
	md5checksum string
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
func (fi bindataFileInfo) MD5Checksum() string {
	return fi.md5checksum
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _bindataTemplatesConfightml = []byte(`{{ define "content" }}

    <p>
        The Mesh Configuration Protocol (MCP) server state for this process. MCP can serve multiple different types of snapshots to different clients.
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

    .modal-dialog-content {
        background-color: #5a5a5a;
    }
    .modal-dialog-content-body {
        white-space: pre-wrap;
        width: 500px;
        word-break: break-all;
    }
    .unsync_error {
        background-color: red;
    }
    </style>

    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="collapse navbar-collapse" id="navbarSupportedContent">
            <ul class="navbar-nav mr-auto">
                {{ range $value := .Groups }}
                    <li class="nav-item" id="nav-{{$value}}">
                        <a class="nav-link" href="#" onclick="refreshRecentRequests('{{$value}}')">{{$value}}</a>
                    </li>
                {{end}}
            </ul>
        </div>
    </nav>

    <div class="modal fade" id="mcpResourceModal" tabindex="-1" role="dialog" aria-labelledby="mcpResourceModalLabel" aria-hidden="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content modal-dialog-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="mcpResourceModalLabel"></h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body modal-dialog-content-body" id="mcpResourceBody">
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <div>
        <table id="recent-requests-table">
            <thead>
            <tr>
                <th>Collection</th>
                <th>Version</th>
                <th>Resources</th>
                <th>Connections</th>
            </tr>
            </thead>

            <tbody>
            </tbody>
        </table>
    </div>
{{ template "last-refresh" .}}

<script>
    "use strict";

    var defaultGroup = '{{index .Groups 0}}';

    function resetActiveTab(tabId) {
        var tabs = document.getElementsByClassName("nav-item");
        tabId = "nav-" + tabId;
        for (var i = 0; i < tabs.length; i++) {
            if (tabs[i].id === tabId) {
                tabs[i].className = "nav-item active";
            } else {
                tabs[i].className = "nav-item";
            }
        }
    }

    function refreshRecentRequests(group) {
        //reset the default group to ensure refresh the desired data
        defaultGroup = group

        //reset the selected tab
        resetActiveTab(group)

        var url = window.location.protocol + "//" + window.location.host + "/configj?group="+group;

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

                if (null != data.Snapshots) {
                    for (var i = 0; i < data.Snapshots.length; i++) {
                        var row = document.createElement("tr");

                        var c1 = document.createElement("td");
                        c1.innerText = data.Snapshots[i].Collection;
                        row.appendChild(c1);

                        var c2 = document.createElement("td");
                        c2.innerText = data.Snapshots[i].Version;
                        row.appendChild(c2);

                        var c3 = document.createElement("td");
                        var c3_ul = document.createElement("ul");
                        for (var j = 0; j < data.Snapshots[i].Names.length; j++) {
                            var c3_li = document.createElement("li");
                            var c3_li_a = document.createElement("a");
                            c3_li_a.dataId = data.Snapshots[i].Collection;
                            c3_li_a.href = "#";
                            c3_li_a.onclick = function(e) {
                                popupResource(group, this.dataId, this.innerText);
                                e.preventDefault();
                            }
                            c3_li_a.innerText =  data.Snapshots[i].Names[j];
                            c3_li.appendChild(c3_li_a);
                            c3_ul.appendChild(c3_li);
                        }
                        c3.appendChild(c3_ul)
                        row.appendChild(c3);

                        var c4 = document.createElement("td");
                        var c4_ul = document.createElement("ul");
                        for (var addr in data.Snapshots[i].Synced) {
                            var c4_li = document.createElement("li");
                            c4_li.innerText =  addr + " " + (data.Snapshots[i].Synced[addr] ? "Synced": "Unsynced");
                            if (!data.Snapshots[i].Synced[addr]) {
                                c4_li.className = "unsync_error";
                            } 
                            c4_ul.appendChild(c4_li);
                        }
                        c4.appendChild(c4_ul)
                        row.appendChild(c4);

                        tbody.appendChild(row)
                    }
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

    refreshRecentRequests(defaultGroup);
    window.setInterval(refreshRecentRequests(defaultGroup), 1000);

    function popupResource(group, collection, name) {

        var url = window.location.protocol + "//" + window.location.host + "/configj/resource?group="+group+"&collection="+collection+"&name="+name;

        var ajax = new XMLHttpRequest();
        ajax.onload = onload;
        ajax.onerror = onerror;
        ajax.open("GET", url, true);
        ajax.send();

        function onload() {
            if (this.status == 200) { // request succeeded
                var data = JSON.parse(this.responseText);

                document.getElementById("mcpResourceModalLabel").innerText = name;
                document.getElementById("mcpResourceBody").innerText = JSON.stringify(data, null, 4);
                $("#mcpResourceModal").modal()
            }
        }

        function onerror(e) {
            console.error(e);
        }
    }

</script>

{{ end }}
`)

func bindataTemplatesConfightmlBytes() ([]byte, error) {
	return _bindataTemplatesConfightml, nil
}



func bindataTemplatesConfightml() (*asset, error) {
	bytes, err := bindataTemplatesConfightmlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{
		name: "templates/config.html",
		size: 0,
		md5checksum: "",
		mode: os.FileMode(0),
		modTime: time.Unix(0, 0),
	}

	a := &asset{bytes: bytes, info: info}

	return a, nil
}


//
// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
//
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
}

//
// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
// nolint: deadcode
//
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

//
// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or could not be loaded.
//
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
}

//
// AssetNames returns the names of the assets.
// nolint: deadcode
//
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

//
// _bindata is a table, holding each asset generator, mapped to its name.
//
var _bindata = map[string]func() (*asset, error){
	"templates/config.html": bindataTemplatesConfightml,
}

//
// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
//
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, &os.PathError{
					Op: "open",
					Path: name,
					Err: os.ErrNotExist,
				}
			}
		}
	}
	if node.Func != nil {
		return nil, &os.PathError{
			Op: "open",
			Path: name,
			Err: os.ErrNotExist,
		}
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

var _bintree = &bintree{Func: nil, Children: map[string]*bintree{
	"templates": {Func: nil, Children: map[string]*bintree{
		"config.html": {Func: bindataTemplatesConfightml, Children: map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
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

// RestoreAssets restores an asset under the given directory recursively
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
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
