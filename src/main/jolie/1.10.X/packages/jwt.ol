type CreateJWTokenRequest:void{
    .registeredClaims?:void{
        .sub?:string
        .iss?:string
        .exp?:long
        .nbf?:long
        .iat?:long
    }
    .userClaims*:void{
        .name:string
        .value:any
    }
}

type CreateJWTokenResponse:void{
    .jwt:string
}

type ReadJWTokenRequest :void{
    .jwt:string
}

type ReadJWTokenResponse:void{
    .registeredClaims?:void{
        .sub?:string
        .iss?:string
        .exp?:long
        .nbf?:long
        .iat?:long
    }
    .userClaims*:void{
        .name:string
        .value:any
    }
}

type SetSignerRequest:void{
    signed:void{
        keystore?:void{
            filename:string
            keystorePass:string
            alias:string
        }
        jsonstore?:void{
            filename:string
        }
    }
}

type SetSignerResponse:void

type SetVerifierRequest:void{
    signed:void{
        certificate?:string
        jwk?:string    
    }
}

type SetVerifierResponse:void


interface JwtInterface{
    RequestResponse:
     createJWToken(CreateJWTokenRequest)(CreateJWTokenResponse) throws IOException,
     readJWToken(ReadJWTokenRequest)(ReadJWTokenResponse) throws IOException WrongSignature,
     setSigner(SetSignerRequest)(SetSignerResponse) throws IOException KeyStoreException FileNotFound CertificateException NoSuchAlgorithmException JOSEException,
     setVerifier (SetVerifierRequest)(SetVerifierResponse) throws CertificateException JOSEException FileNotFound
}



service JWT {
  
inputPort ip {
        location:"local"
        interfaces: JwtInterface
    }

foreign java {
  class: "joliex.jwt.JwtService" 
  }
}


