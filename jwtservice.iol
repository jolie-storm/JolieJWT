type CreateJwt:void{
    .registeredClaims:void{
        .iss?:string
        .sub?:string
        .aud?:string
        .exp?:long
        .nbf?:long
        .iat?:long
        .jti?:long
    }
    .userClaims*:void{
        .name:string
        .value:any
    }
    .signed?:void{
        .keystore:string
        .keystorePass:string
    }
}

type ReadJwt:void{
    .jwt:string
    .signed?:void{
        .keystore:string
        .keystorePass:string
    }
}
type initJwt:void{

    .signed?:void{
        .keystore:string
        .keystorePass:string
    }
}