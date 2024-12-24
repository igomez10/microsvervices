# URLApi

All URIs are relative to *https://urlshortener.gomezignacio.com*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**createUrl**](URLApi.md#createUrl) | **POST** /v1/urls | Create a new url |
| [**deleteUrl**](URLApi.md#deleteUrl) | **DELETE** /v1/urls/{alias} | Delete a url |
| [**getUrl**](URLApi.md#getUrl) | **GET** /v1/urls/{alias} | Get a url |
| [**getUrlData**](URLApi.md#getUrlData) | **GET** /v1/urls/{alias}/data | Returns a url metadata |


<a name="createUrl"></a>
# **createUrl**
> URL createUrl(URL, X-Request-ID)

Create a new url

    Returns a url

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **URL** | [**URL**](../Models/URL.md)| Create a new url | |
| **X-Request-ID** | **String**| Request ID | [optional] [default to null] |

### Return type

[**URL**](../Models/URL.md)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

<a name="deleteUrl"></a>
# **deleteUrl**
> deleteUrl(alias, X-Request-ID)

Delete a url

    Delete a url

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **alias** | **String**| The alias of the url | [default to null] |
| **X-Request-ID** | **String**| Request ID | [optional] [default to null] |

### Return type

null (empty response body)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="getUrl"></a>
# **getUrl**
> getUrl(alias, X-Request-ID)

Get a url

    Returns a url

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **alias** | **String**| The alias of the url | [default to null] |
| **X-Request-ID** | **String**| Request ID | [optional] [default to null] |

### Return type

null (empty response body)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="getUrlData"></a>
# **getUrlData**
> URL getUrlData(alias, X-Request-ID)

Returns a url metadata

    Returns a url

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **alias** | **String**| The alias of the url | [default to null] |
| **X-Request-ID** | **String**| Request ID | [optional] [default to null] |

### Return type

[**URL**](../Models/URL.md)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

