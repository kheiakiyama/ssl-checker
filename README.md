## Usage
```
go build

./ssl-checker -host=example.com
```

### Output Example
```
{  
   "Host":"cv.kheiakiyama.com",
   "Enabled":true,
   "Version":{  
      "SSL30":false,
      "TLS10":true,
      "TLS11":true,
      "TLS12":true
   },
   "Cliper":{  
      "TLS_RSA_WITH_RC4_128_SHA":false,
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA":false,
      "TLS_RSA_WITH_AES_128_CBC_SHA":true,
      "TLS_RSA_WITH_AES_256_CBC_SHA":true,
      "TLS_RSA_WITH_AES_128_CBC_SHA256":true,
      "TLS_RSA_WITH_AES_128_GCM_SHA256":true,
      "TLS_RSA_WITH_AES_256_GCM_SHA384":true,
      "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":false,
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":false,
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":false,
      "TLS_ECDHE_RSA_WITH_RC4_128_SHA":false,
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":false,
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":true,
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":true,
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":false,
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":true,
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":true,
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":false,
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":true,
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":false,
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":false,
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":false
   },
   "CurvePreferences":{  
      "X25519":true,
      "CurveP256":true,
      "CurveP384":true,
      "CurveP521":true
   },
   "ExpireDateUtc":"2019-07-08T12:00:00Z"
}
```
