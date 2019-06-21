# Oauth2 library for Joomla! 4

	1. Introduction
	2. Instalation
	3. How it works


## 1. Introduction
---------------

The OAuth 2.0 for Joomla Api Application is based on a Louis Landry work about 
oauth1 server suport for Joomla! Platform.

```
https://github.com/LouisLandry/joomla-platform/tree/9bc988185ccc3e1c437256cc2c927e49312b3d00/libraries/joomla/oauth1
```
Also this library is based on RFC 6849 (http://tools.ietf.org/html/rfc6749)


This is the basic graph of how is the process of the authentication using OAuth 2.0:

```
 +-------------------------+                                         +-----------------------------+
 |      Client             |                                         |         Server              |
 |-------------------------|                                         |-----------------------------|
 |                         |                                         |                             |
 | Request temporary token.| +---------------GET------------------>  | Receive request and send    |
 |                         |                                         | the temporary token.        |
 | Get the temporary token | <-JSON-------------------------------+  |                             |
 | and send authorization  |                                         |                             |
 | request.                | +---------------POST----------------->  | Authorise or deny and return|
 |                         |                                         | the status and new temporary|
 | Get the status and the  | <-JSON-------------------------------+  | token.                      |
 | new temporary token,    |                                         |                             |
 | then request the access | +---------------POST----------------->  | Compare temporary token and |
 | token.                  |                                         | authentication and return   |
 |                         |                                         | the access token.           |
 | Get the access token for| <-JSON-------------------------------+  |                             |
 | request protected       |                                         |                             |
 | resources.              |                                         |                             |
 |                         |                                         |                             |
 |                         |                                         |                             |
 +-------------------------+                                         +-----------------------------+
```

## 2. Installation
------------------

* Install a new Joomla! 4 installation
* Configure composer minimum-stability and prefer-stable

```
$ composer config minimum-stability dev

$ composer config prefer-stable true
```
* Install Oauth2 libraries

```
$ composer require "matware-lab/oauth2:dev-master"
```

* Install api-authentication plugin copying https://github.com/matware-lab/oauth2/tree/master/www/plugins/api-authentication/oauth2 to your `JPATH_ROOT/plugins/api-authentication` folder and discover it

* Disable Joomla! Basic authentication

## 3. How it works
------------------

To get one access token to get your private resource, its needed to perform 3 GET or POST request. 

### Temporary token

**Parameters**

* oauth_response_type= temporary
* oauth_client_id= ZmFzdHNsYWNrOg==
* oauth_client_secret= WW1Ga05UUXhNekkyTUcOaE5tRTNaVGt6WldZellqRdNNek5tWldNNE16TT06YlhsclNtTXdlVlZLT1cwb2QzMTFhMDVNYm1ZNg==
* oauth_signature_method= PLAINTEXT

```
curl -X GET \
  'http://joomla40.test/api/index.php/v1/article?oauth_response_type=temporary&oauth_client_id=ZmFzdHNsYWNrOg==&oauth_client_secret=WW1Ga05UUXhNekkyTUcOaE5tRTNaVGt6WldZellqRdNNek5tWldNNE16TT06YlhsclNtTXdlVlZLT1cwb2QzMTFhMDVNYm1ZNg==&oauth_signature_method=PLAINTEXT' \
  -H 'Accept: */*' \
  -H 'Authorization: Bearer Basic ZWxhc3RpYzpjaGFuZ2VtZQ==' \
  -H 'Cache-Control: no-cache' \
  -H 'Connection: keep-alive' \
  -H 'Host: joomla40.test' \
  -H 'PHP_AUTH_PW: JOOMLAPASSWORD' \
  -H 'PHP_AUTH_USER: JOOMLAUSERNAME' \
  -H 'Postman-Token: 25dcb4a9-90e5-4c6c-883d-86321da9e00c,7c94eb6f-7f46-4507-9524-b4c80c65a3af' \
  -H 'User-Agent: PostmanRuntime/7.15.0' \
  -H 'accept-encoding: gzip, deflate' \
  -H 'cache-control: no-cache' \
  -H 'cookie: 91a11700197c2613cccdfa4ed11ded00=0icb9v3vkmqn77agqb8gd41hgn' \
  -b 91a11700197c2613cccdfa4ed11ded00=0icb9v3vkmqn77agqb8gd41hgn
  ```
  
  **Response:** `{"oauth_code":"c0a2c2eae9c8a29add5d8d8b0342532d","oauth_state":true}`

### Authorise token

**Parameters**

* oauth_response_type= temporary
* oauth_client_id= ZmFzdHNsYWNrOg==
* oauth_client_secret= WW1Ga05UUXhNekkyTUcOaE5tRTNaVGt6WldZellqRdNNek5tWldNNE16TT06YlhsclNtTXdlVlZLT1cwb2QzMTFhMDVNYm1ZNg==
* oauth_signature_method= PLAINTEXT
* oauth_code= c0a2c2eae9c8a29add5d8d8b0342532d

  **Response:** `{"oauth_code":"5484f5657786c1c64a81cbf5b5af21ed","oauth_state":true}`

### Access token

**Parameters**

* oauth_response_type= token
* oauth_client_id= ZmFzdHNsYWNrOg==
* oauth_client_secret= WW1Ga05UUXhNekkyTUcOaE5tRTNaVGt6WldZellqRdNNek5tWldNNE16TT06YlhsclNtTXdlVlZLT1cwb2QzMTFhMDVNYm1ZNg==
* oauth_signature_method= PLAINTEXT
* oauth_code= c0a2c2eae9c8a29add5d8d8b0342532d

  **Response:** `{"access_token":"fad0feb70b053f02f4ecdd2ff06de531","expires_in":"PT4H","refresh_token":"a3de34aed76f98a6f5d158262154be69"}`
