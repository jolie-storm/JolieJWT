package joliex.jwt;

import jolie.runtime.FaultException;
import jolie.runtime.Value;
import jolie.runtime.embedding.RequestResponse;
import junit.framework.TestCase;

public class JwtServiceTest extends TestCase {

    public void testSetSigner() throws FaultException {

  /*      JwtService jwtService = new JwtService();
        Value setSignerValue = Value.create();
        setSignerValue.getFirstChild("signed").getFirstChild("keystore").getFirstChild("filename").setValue("clientkeystore");
        setSignerValue.getFirstChild("signed").getFirstChild("keystore").getFirstChild("keystorePass").setValue("test01");
        setSignerValue.getFirstChild("signed").getFirstChild("keystore").getFirstChild("alias").setValue("client");
        jwtService.setSigner(setSignerValue);

        setSignerValue = Value.create();
        setSignerValue.getFirstChild("signed").getFirstChild("jsonstore").getFirstChild("filename").setValue("jvproject-289212-ce3b03a915fd.json");
        jwtService.setSigner(setSignerValue);*/
    }

    public void testCreateJWToken() throws FaultException {

  /*      JwtService jwtService = new JwtService();
        Value setSignerValue = Value.create();
        setSignerValue.getFirstChild("signed").getFirstChild("keystore").getFirstChild("filename").setValue("clientkeystore");
        setSignerValue.getFirstChild("signed").getFirstChild("keystore").getFirstChild("keystorePass").setValue("test01");
        setSignerValue.getFirstChild("signed").getFirstChild("keystore").getFirstChild("alias").setValue("client");
        jwtService.setSigner(setSignerValue);


        Value requestCreateJWT = Value.create();
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("sub").setValue("test");
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("sub").setValue("test");
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("iss").setValue("jolie");
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("exp").setValue(1612732560404L);
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("iat").setValue(1612732760404L);
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("iat").setValue(1612732760404L);

        Value userClaim = Value.create();
        userClaim.getFirstChild("name").setValue("role");
        userClaim.getFirstChild("value").setValue("admin");
        requestCreateJWT.getChildren("userClaims").add(userClaim);

        Value response = jwtService.createJWToken(requestCreateJWT);
        System.out.println(response.getFirstChild("jwt").strValue());

   */

    }

    public void testReadJWToken() throws FaultException {

    /*    JwtService jwtService = new JwtService();
        Value setSignerValue = Value.create();
        setSignerValue.getFirstChild("signed").getFirstChild("keystore").getFirstChild("filename").setValue("clientkeystore");
        setSignerValue.getFirstChild("signed").getFirstChild("keystore").getFirstChild("keystorePass").setValue("test01");
        setSignerValue.getFirstChild("signed").getFirstChild("keystore").getFirstChild("alias").setValue("client");
        jwtService.setSigner(setSignerValue);


        Value requestCreateJWT = Value.create();
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("sub").setValue("test");
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("sub").setValue("test");
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("iss").setValue("jolie");
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("exp").setValue(1612732560404L);
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("iat").setValue(1612732760404L);
        requestCreateJWT.getFirstChild("registeredClaims").getFirstChild("iat").setValue(1612732760404L);

        Value userClaim = Value.create();
        userClaim.getFirstChild("name").setValue("role");
        userClaim.getFirstChild("value").setValue("admin");
        requestCreateJWT.getChildren("userClaims").add(userClaim);

        Value responseCreateJWT = jwtService.createJWToken(requestCreateJWT);
        System.out.println(responseCreateJWT.getFirstChild("jwt").strValue());

        Value setVerifierValue = Value.create();
        setVerifierValue.getFirstChild("signed").getFirstChild("certificate").setValue("publicKey.pem");
        jwtService.setVerifier(setVerifierValue);

        Value readJwtValueRequest = Value.create();
        readJwtValueRequest.getFirstChild("jwt").setValue(responseCreateJWT.getFirstChild("jwt").strValue());
        Value responseReadJWT = jwtService.readJWToken(readJwtValueRequest);
        System.out.println(responseReadJWT.getFirstChild("registeredClaims").getFirstChild("sub").strValue());*/
    }

    public void testSetVerifier() throws FaultException {

   /*     JwtService jwtService = new JwtService();
        Value setVerifierValue = Value.create();
        setVerifierValue.getFirstChild("signed").getFirstChild("certificate").setValue("publicKey.pem");
        jwtService.setVerifier(setVerifierValue);*/

    }
}