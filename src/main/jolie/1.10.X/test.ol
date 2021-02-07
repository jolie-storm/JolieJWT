from  "./packages/jwt" import JWT

service TestService{
    embed JWT  as JWT
    main{

        request.signed.keystore.filename = "keystore.p12"
        request.signed.keystore.keystorePass = "ibebubis"
        request.signed.keystore.alias = "pixis"
        setSigner@JWT( request )(  );
        
        undef (request)
        request.signed.certificate = "keystore.pem"
        setVerifier@JWT( request )(  )
        undef (request)

        request.registeredClaims.sub = "pixis"
        request.registeredClaims.iss = "pixis"
        request.registeredClaims.exp = 1000000000L   
        request.userClaims[0].name="role"
        request.userClaims[0].value="user"
        request.userClaims[1].name="userId"
        request.userClaims[1].value=1
        request.userClaims[2].name="device"
        request.userClaims[2].value="Ios"

        createJWToken@JWT(request)(responseCreate)

        readRequest << responseCreate
        readJWToken@JWT( readRequest )(  )

    }
}