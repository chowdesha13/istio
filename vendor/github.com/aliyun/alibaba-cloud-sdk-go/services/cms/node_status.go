package cms

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
)

// NodeStatus invokes the cms.NodeStatus API synchronously
// api document: https://help.aliyun.com/api/cms/nodestatus.html
func (client *Client) NodeStatus(request *NodeStatusRequest) (response *NodeStatusResponse, err error) {
	response = CreateNodeStatusResponse()
	err = client.DoAction(request, response)
	return
}

// NodeStatusWithChan invokes the cms.NodeStatus API asynchronously
// api document: https://help.aliyun.com/api/cms/nodestatus.html
// asynchronous document: https://help.aliyun.com/document_detail/66220.html
func (client *Client) NodeStatusWithChan(request *NodeStatusRequest) (<-chan *NodeStatusResponse, <-chan error) {
	responseChan := make(chan *NodeStatusResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.NodeStatus(request)
		if err != nil {
			errChan <- err
		} else {
			responseChan <- response
		}
	})
	if err != nil {
		errChan <- err
		close(responseChan)
		close(errChan)
	}
	return responseChan, errChan
}

// NodeStatusWithCallback invokes the cms.NodeStatus API asynchronously
// api document: https://help.aliyun.com/api/cms/nodestatus.html
// asynchronous document: https://help.aliyun.com/document_detail/66220.html
func (client *Client) NodeStatusWithCallback(request *NodeStatusRequest, callback func(response *NodeStatusResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *NodeStatusResponse
		var err error
		defer close(result)
		response, err = client.NodeStatus(request)
		callback(response, err)
		result <- 1
	})
	if err != nil {
		defer close(result)
		callback(nil, err)
		result <- 0
	}
	return result
}

// NodeStatusRequest is the request struct for api NodeStatus
type NodeStatusRequest struct {
	*requests.RpcRequest
	InstanceId string `position:"Query" name:"InstanceId"`
}

// NodeStatusResponse is the response struct for api NodeStatus
type NodeStatusResponse struct {
	*responses.BaseResponse
	ErrorCode    int    `json:"ErrorCode" xml:"ErrorCode"`
	ErrorMessage string `json:"ErrorMessage" xml:"ErrorMessage"`
	Success      bool   `json:"Success" xml:"Success"`
	RequestId    string `json:"RequestId" xml:"RequestId"`
	InstanceId   string `json:"InstanceId" xml:"InstanceId"`
	AutoInstall  bool   `json:"AutoInstall" xml:"AutoInstall"`
	Status       string `json:"Status" xml:"Status"`
}

// CreateNodeStatusRequest creates a request to invoke NodeStatus API
func CreateNodeStatusRequest() (request *NodeStatusRequest) {
	request = &NodeStatusRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Cms", "2018-03-08", "NodeStatus", "cms", "openAPI")
	return
}

// CreateNodeStatusResponse creates a response to parse from NodeStatus response
func CreateNodeStatusResponse() (response *NodeStatusResponse) {
	response = &NodeStatusResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}
