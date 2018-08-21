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

// EnableActiveAlert invokes the cms.EnableActiveAlert API synchronously
// api document: https://help.aliyun.com/api/cms/enableactivealert.html
func (client *Client) EnableActiveAlert(request *EnableActiveAlertRequest) (response *EnableActiveAlertResponse, err error) {
	response = CreateEnableActiveAlertResponse()
	err = client.DoAction(request, response)
	return
}

// EnableActiveAlertWithChan invokes the cms.EnableActiveAlert API asynchronously
// api document: https://help.aliyun.com/api/cms/enableactivealert.html
// asynchronous document: https://help.aliyun.com/document_detail/66220.html
func (client *Client) EnableActiveAlertWithChan(request *EnableActiveAlertRequest) (<-chan *EnableActiveAlertResponse, <-chan error) {
	responseChan := make(chan *EnableActiveAlertResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.EnableActiveAlert(request)
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

// EnableActiveAlertWithCallback invokes the cms.EnableActiveAlert API asynchronously
// api document: https://help.aliyun.com/api/cms/enableactivealert.html
// asynchronous document: https://help.aliyun.com/document_detail/66220.html
func (client *Client) EnableActiveAlertWithCallback(request *EnableActiveAlertRequest, callback func(response *EnableActiveAlertResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *EnableActiveAlertResponse
		var err error
		defer close(result)
		response, err = client.EnableActiveAlert(request)
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

// EnableActiveAlertRequest is the request struct for api EnableActiveAlert
type EnableActiveAlertRequest struct {
	*requests.RpcRequest
	Product string `position:"Query" name:"Product"`
	UserId  string `position:"Query" name:"UserId"`
}

// EnableActiveAlertResponse is the response struct for api EnableActiveAlert
type EnableActiveAlertResponse struct {
	*responses.BaseResponse
	Success bool   `json:"Success" xml:"Success"`
	Code    string `json:"Code" xml:"Code"`
	Message string `json:"Message" xml:"Message"`
}

// CreateEnableActiveAlertRequest creates a request to invoke EnableActiveAlert API
func CreateEnableActiveAlertRequest() (request *EnableActiveAlertRequest) {
	request = &EnableActiveAlertRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Cms", "2018-03-08", "EnableActiveAlert", "cms", "openAPI")
	return
}

// CreateEnableActiveAlertResponse creates a response to parse from EnableActiveAlert response
func CreateEnableActiveAlertResponse() (response *EnableActiveAlertResponse) {
	response = &EnableActiveAlertResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}
