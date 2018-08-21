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

// TaskConfigEnable invokes the cms.TaskConfigEnable API synchronously
// api document: https://help.aliyun.com/api/cms/taskconfigenable.html
func (client *Client) TaskConfigEnable(request *TaskConfigEnableRequest) (response *TaskConfigEnableResponse, err error) {
	response = CreateTaskConfigEnableResponse()
	err = client.DoAction(request, response)
	return
}

// TaskConfigEnableWithChan invokes the cms.TaskConfigEnable API asynchronously
// api document: https://help.aliyun.com/api/cms/taskconfigenable.html
// asynchronous document: https://help.aliyun.com/document_detail/66220.html
func (client *Client) TaskConfigEnableWithChan(request *TaskConfigEnableRequest) (<-chan *TaskConfigEnableResponse, <-chan error) {
	responseChan := make(chan *TaskConfigEnableResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.TaskConfigEnable(request)
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

// TaskConfigEnableWithCallback invokes the cms.TaskConfigEnable API asynchronously
// api document: https://help.aliyun.com/api/cms/taskconfigenable.html
// asynchronous document: https://help.aliyun.com/document_detail/66220.html
func (client *Client) TaskConfigEnableWithCallback(request *TaskConfigEnableRequest, callback func(response *TaskConfigEnableResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *TaskConfigEnableResponse
		var err error
		defer close(result)
		response, err = client.TaskConfigEnable(request)
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

// TaskConfigEnableRequest is the request struct for api TaskConfigEnable
type TaskConfigEnableRequest struct {
	*requests.RpcRequest
	IdList  *[]string        `position:"Query" name:"IdList"  type:"Repeated"`
	Enabled requests.Boolean `position:"Query" name:"Enabled"`
}

// TaskConfigEnableResponse is the response struct for api TaskConfigEnable
type TaskConfigEnableResponse struct {
	*responses.BaseResponse
	ErrorCode    int    `json:"ErrorCode" xml:"ErrorCode"`
	ErrorMessage string `json:"ErrorMessage" xml:"ErrorMessage"`
	Success      bool   `json:"Success" xml:"Success"`
	RequestId    string `json:"RequestId" xml:"RequestId"`
}

// CreateTaskConfigEnableRequest creates a request to invoke TaskConfigEnable API
func CreateTaskConfigEnableRequest() (request *TaskConfigEnableRequest) {
	request = &TaskConfigEnableRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Cms", "2018-03-08", "TaskConfigEnable", "cms", "openAPI")
	return
}

// CreateTaskConfigEnableResponse creates a response to parse from TaskConfigEnable response
func CreateTaskConfigEnableResponse() (response *TaskConfigEnableResponse) {
	response = &TaskConfigEnableResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}
