# \URLAPI

All URIs are relative to *https://socialapp.gomezignacio.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreateUrl**](URLAPI.md#CreateUrl) | **Post** /v1/urls | Create a new url
[**DeleteUrl**](URLAPI.md#DeleteUrl) | **Delete** /v1/urls/{alias} | Delete a url
[**GetUrl**](URLAPI.md#GetUrl) | **Get** /v1/urls/{alias} | Get a url
[**GetUrlData**](URLAPI.md#GetUrlData) | **Get** /v1/urls/{alias}/data | Returns a url metadata



## CreateUrl

> URL CreateUrl(ctx).URL(uRL).Execute()

Create a new url



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/igomez10/microservices/socialapp/client"
)

func main() {
	uRL := *openapiclient.NewURL("Url_example", "Alias_example") // URL | Create a new url

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.URLAPI.CreateUrl(context.Background()).URL(uRL).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `URLAPI.CreateUrl``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateUrl`: URL
	fmt.Fprintf(os.Stdout, "Response from `URLAPI.CreateUrl`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCreateUrlRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **uRL** | [**URL**](URL.md) | Create a new url | 

### Return type

[**URL**](URL.md)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteUrl

> DeleteUrl(ctx, alias).Execute()

Delete a url



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/igomez10/microservices/socialapp/client"
)

func main() {
	alias := "abcdef" // string | The alias of the url

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.URLAPI.DeleteUrl(context.Background(), alias).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `URLAPI.DeleteUrl``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**alias** | **string** | The alias of the url | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteUrlRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

 (empty response body)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetUrl

> GetUrl(ctx, alias).Execute()

Get a url



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/igomez10/microservices/socialapp/client"
)

func main() {
	alias := "abcdef" // string | The alias of the url

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.URLAPI.GetUrl(context.Background(), alias).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `URLAPI.GetUrl``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**alias** | **string** | The alias of the url | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetUrlRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

 (empty response body)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetUrlData

> URL GetUrlData(ctx, alias).Execute()

Returns a url metadata



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/igomez10/microservices/socialapp/client"
)

func main() {
	alias := "abcdef" // string | The alias of the url

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.URLAPI.GetUrlData(context.Background(), alias).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `URLAPI.GetUrlData``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetUrlData`: URL
	fmt.Fprintf(os.Stdout, "Response from `URLAPI.GetUrlData`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**alias** | **string** | The alias of the url | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetUrlDataRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**URL**](URL.md)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

