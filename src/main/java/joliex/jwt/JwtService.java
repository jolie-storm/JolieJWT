/*
 * @author Francesco Bullini, Balint Maschio
 */
package joliex.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import jolie.runtime.*;
import jolie.runtime.embedding.RequestResponse;
import org.jetbrains.annotations.NotNull;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;

@CanUseJars({"nimbus-jose-jwt.jar", "json-smart.jar"})

public class JwtService extends JavaService {
    private JWSSigner signer = null;
    private RSAKey rsaPrivateKey = null;
    private JWSVerifier verifier = null;


    @RequestResponse
    public Value setSigner(Value request) throws FaultException {
        Value response = Value.create();
        try {
            if (request.getFirstChild("signed").hasChildren("keystore")) {
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                InputStream is = new FileInputStream(request.getFirstChild("signed").getFirstChild("keystore").getFirstChild("filename").strValue());
                keyStore.load(is, request.getFirstChild("signed").getFirstChild("keystore").getFirstChild("keystorePass").strValue().toCharArray());
                rsaPrivateKey = RSAKey.load(keyStore, request.getFirstChild("signed").getFirstChild("keystore").getFirstChild("alias").strValue(), request.getFirstChild("signed").getFirstChild("keystore").getFirstChild("keystorePass").strValue().toCharArray());
                signer = new RSASSASigner(rsaPrivateKey);
            }

            if (request.getFirstChild("signed").hasChildren("jsonStore")) {
                Path path = Path.of(request.getFirstChild("signed").getFirstChild("jsonstore").getFirstChild("filename").strValue());
                String certificateContent = Files.readString(path);
                rsaPrivateKey = RSAKey.parse(certificateContent);
                signer = new RSASSASigner(rsaPrivateKey);
            }
        } catch (KeyStoreException e) {
            throw new FaultException("KeyStoreException");
        } catch (FileNotFoundException e) {
            throw new FaultException("FileNotFound");
        } catch (CertificateException e) {
            throw new FaultException("CertificateException");
        } catch (NoSuchAlgorithmException e) {
            throw new FaultException("NoSuchAlgorithmException");
        } catch (JOSEException e) {
            throw new FaultException("JOSEException");
        } catch (IOException e) {
            throw new FaultException("IOException");
        } catch (ParseException e) {
            throw new FaultException("ParseException");
        }
        return response;
    }

    public Value setVerifier(Value request) throws FaultException {
        Value response = Value.create();
        RSAKey rsaPublicKey = null;
        try {
            if (request.getFirstChild("signed").hasChildren("certificate")) {
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                FileInputStream is = new FileInputStream(request.getFirstChild("signed").getFirstChild("certificate").strValue());
                X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
                rsaPublicKey = RSAKey.parse(cer);
            } else if (request.getFirstChild("signed").hasChildren("jwk")) {
                rsaPublicKey = RSAKey.parse(request.getFirstChild("signed").getFirstChild("jwk").strValue());

            } else {
                throw new FaultException("CertificateException");
            }

            verifier = new RSASSAVerifier(rsaPublicKey);
        } catch (CertificateException e) {
            throw new FaultException("CertificateException");
        } catch (JOSEException e) {
            throw new FaultException("JOSEException");
        } catch (FileNotFoundException e) {
            throw new FaultException("FileNotFound");
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return response;
    }

    @RequestResponse
    public Value createJWToken(Value request) throws FaultException {
        Value response = Value.create();
        try {
            JWTClaimsSet.Builder jwtClaimsBuilder = new JWTClaimsSet.Builder();
            if (request.getFirstChild("registeredClaims").getFirstChild("sub").isDefined()) {
                jwtClaimsBuilder.subject(request.getFirstChild("registeredClaims").getFirstChild("sub").strValue());
            }
            if (request.getFirstChild("registeredClaims").getFirstChild("iss").isDefined()) {
                jwtClaimsBuilder.issuer(request.getFirstChild("registeredClaims").getFirstChild("iss").strValue());
            }
            if (request.getFirstChild("registeredClaims").getFirstChild("exp").isDefined()) {
                jwtClaimsBuilder.expirationTime(new Date(request.getFirstChild("registeredClaims").getFirstChild("exp").longValue()));
            }
            if (request.getFirstChild("registeredClaims").getFirstChild("nbf").isDefined()) {
                jwtClaimsBuilder.notBeforeTime(new Date(request.getFirstChild("registeredClaims").getFirstChild("nbf").longValue()));
            }
            if (request.getFirstChild("registeredClaims").getFirstChild("iat").isDefined()) {
                jwtClaimsBuilder.issueTime(new Date(request.getFirstChild("registeredClaims").getFirstChild("iat").longValue()));
            }
            ValueVector children = request.getChildren("userClaims");
            for (int counter = 0; counter < children.size(); counter++) {
                if (children.get(counter).getFirstChild("value").isInt()) {
                    jwtClaimsBuilder.claim(children.get(counter).getFirstChild("name").strValue(), children.get(counter).getFirstChild("value").intValue());
                } else if (children.get(counter).getFirstChild("value").isLong()) {
                    jwtClaimsBuilder.claim(children.get(counter).getFirstChild("name").strValue(), children.get(counter).getFirstChild("value").longValue());
                } else if (children.get(counter).getFirstChild("value").isString()) {
                    jwtClaimsBuilder.claim(children.get(counter).getFirstChild("name").strValue(), children.get(counter).getFirstChild("value").strValue());
                } else if (children.get(counter).getFirstChild("value").isBool()) {
                    jwtClaimsBuilder.claim(children.get(counter).getFirstChild("name").strValue(), children.get(counter).getFirstChild("value").boolValue());
                } else if (children.get(counter).getFirstChild("value").isDouble()) {
                    jwtClaimsBuilder.claim(children.get(counter).getFirstChild("name").strValue(), children.get(counter).getFirstChild("value").doubleValue());
                }
            }


            JWTClaimsSet jwtClaimSet = jwtClaimsBuilder.build();
            if (signer != null) {
                SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaPrivateKey.getKeyID()).build(), jwtClaimSet);
                jwt.sign(signer);
                response.getFirstChild("jwt").setValue(jwt.serialize());
            } else {
                PlainJWT jwt = new PlainJWT(jwtClaimSet);
                response.getFirstChild("jwt").setValue(jwt.serialize());
            }

        } catch (JOSEException e) {
            throw new FaultException("JOSEException");
        }
        return response;
    }


    @RequestResponse
    public Value readJWToken(@NotNull Value request) throws FaultException {
        Value returnValue = Value.create();
        try {

            if (verifier != null) {
                SignedJWT jwt = SignedJWT.parse(request.getFirstChild("jwt").strValue());

                if (!jwt.verify(verifier)) {
                    throw new FaultException("WrongSignature");
                }

                if (!jwt.getJWTClaimsSet().getSubject().isEmpty()) {
                    returnValue.getFirstChild("registeredClaims").getFirstChild("sub").setValue(jwt.getJWTClaimsSet().getSubject());
                }
                if (!jwt.getJWTClaimsSet().getIssuer().isEmpty()) {
                    returnValue.getFirstChild("registeredClaims").getFirstChild("iss").setValue(jwt.getJWTClaimsSet().getIssuer());
                }
                if (jwt.getJWTClaimsSet().getExpirationTime() != null) {
                    returnValue.getFirstChild("registeredClaims").getFirstChild("exp").setValue(jwt.getJWTClaimsSet().getExpirationTime().getTime());
                }
                jwt.getJWTClaimsSet().getClaims().forEach((s, o) -> {
                    Value userClaim = Value.create();
                    if (!(s.equals("sub") | s.equals("iss") | s.equals("exp"))) {
                        userClaim.getFirstChild("name").setValue(s);
                        if (o instanceof Integer) {
                            userClaim.getFirstChild("value").setValue((Integer) o);
                        } else if (o instanceof Long) {
                            userClaim.getFirstChild("value").setValue((Long) o);
                        } else if (o instanceof String) {
                            userClaim.getFirstChild("value").setValue((String) o);
                        } else if (o instanceof Double) {
                            userClaim.getFirstChild("value").setValue((Double) o);
                        } else if (o instanceof Boolean) {
                            userClaim.getFirstChild("value").setValue((Boolean) o);
                        } else if (o instanceof ArrayList) {
                            for (int counter = 0; counter < ((ArrayList) o).size(); counter++) {
                                if (((ArrayList) o).get(counter) instanceof String) {
                                    String obj = String.valueOf(((ArrayList) o).get(counter));
                                    userClaim.getChildren("value").add(Value.create(obj));
                                }
                            }
                        }
                        returnValue.getChildren("userClaims").set(returnValue.getChildren("userClaims").size(), userClaim);
                    }
                });

            } else {
                PlainJWT jwt = PlainJWT.parse(request.getFirstChild("jwt").strValue());

                if (!jwt.getJWTClaimsSet().getSubject().isEmpty()) {
                    returnValue.getFirstChild("registeredClaims").getFirstChild("sub").setValue(jwt.getJWTClaimsSet().getSubject());
                }
                if (!jwt.getJWTClaimsSet().getIssuer().isEmpty()) {
                    returnValue.getFirstChild("registeredClaims").getFirstChild("iss").setValue(jwt.getJWTClaimsSet().getIssuer());
                }
                if (jwt.getJWTClaimsSet().getExpirationTime() != null) {
                    returnValue.getFirstChild("registeredClaims").getFirstChild("exp").setValue(jwt.getJWTClaimsSet().getExpirationTime().getTime());
                }

                jwt.getJWTClaimsSet().getClaims().forEach((s, o) -> {
                    Value userClaim = Value.create();
                    if (!(s.equals("sub") | s.equals("iss") | s.equals("exp"))) {
                        userClaim.getFirstChild("name").setValue(s);
                        if (o instanceof Integer) {
                            userClaim.getFirstChild("value").setValue((Integer) o);
                        } else if (o instanceof Long) {
                            userClaim.getFirstChild("value").setValue((Long) o);
                        } else if (o instanceof String) {
                            userClaim.getFirstChild("value").setValue((String) o);
                        } else if (o instanceof Double) {
                            userClaim.getFirstChild("value").setValue((Double) o);
                        } else if (o instanceof Boolean) {
                            userClaim.getFirstChild("value").setValue((Boolean) o);
                        }
                        returnValue.getChildren("userClaims").set(returnValue.getChildren("userClaims").size(), userClaim);
                    }
                });
            }
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return returnValue;

    }

    public static void main(String[] arg) throws FaultException {
        JwtService jwtService = new JwtService();

        Value setSignerValue = Value.create();
        setSignerValue.getFirstChild("signed").getFirstChild("keystore").setValue("jvproject-289212-b003acb744dd.p12");
        setSignerValue.getFirstChild("signed").getFirstChild("keystorePass").setValue("notasecret");
        setSignerValue.getFirstChild("signed").getFirstChild("alias").setValue("privatekey");

        try {
            jwtService.setSigner(setSignerValue);
        } catch (FaultException e) {
            e.printStackTrace();
        }


   /*
        JwtService jwtService = new JwtService();
        Value setVerifierValue = Value.create();
        setVerifierValue.getFirstChild("signed").getFirstChild("jwk").setValue("{\"kid\":\"X5eXk4xyojNFum1kl2Ytv8dlNP4-c57dO6QGTVBwaNk\",\"nbf\":1493763266,\"use\":\"sig\",\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw\"}");

        try {
            jwtService.setVerifier(setVerifierValue);

            Value requestReadJwt = Value.create();
            requestReadJwt.getFirstChild("jwt").setValue("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ilg1ZVhrNHh5b2pORnVtMWtsMll0djhkbE5QNC1jNTdkTzZRR1RWQndhTmsifQ.eyJpc3MiOiJodHRwczovL3BpeGlzanYuYjJjbG9naW4uY29tLzg3NWI4MDJjLTk1NzgtNDljNS1iNTEyLTYzYmY2MjVlNjM5Zi92Mi4wLyIsImV4cCI6MTYwMDQ0NTc3NSwibmJmIjoxNjAwNDQyMTc1LCJhdWQiOiI1OGEyYTMxMC00ODMwLTQwYzMtODE2MC1iM2E0YmNhNGE2ZDMiLCJvaWQiOiIzOTU4YTBiOS0wNzI5LTRhNTgtYTRlNy0xZWY1ZTlkZTg4NTkiLCJzdWIiOiIzOTU4YTBiOS0wNzI5LTRhNTgtYTRlNy0xZWY1ZTlkZTg4NTkiLCJjaXR5IjoiR2Fib24gQ2l0eSIsImNvdW50cnkiOiJHYWJvbiIsImdpdmVuX25hbWUiOiJCYWxpbnQiLCJmYW1pbHlfbmFtZSI6Ik1hc2NoaW8iLCJ0ZnAiOiJCMkNfMV9zaWdudXBzaWduaW4xIiwibm9uY2UiOiJhZTAzN2I5ZS0xZWFmLTRiNDctYWQ3Zi01YjQwMGFiZGEwOTMiLCJzY3AiOiJ1c2VyLmFjY2VzcyIsImF6cCI6ImEyNjg4Nzk0LWRiNjktNDEyNy04NzA1LTY4NmU3ZTkwOTJhZiIsInZlciI6IjEuMCIsImlhdCI6MTYwMDQ0MjE3NX0.qXpoWaLJBTeLZEzjk7cDzeDqeJ1JTnnT5JPLNqQfPtGzFrWivajcccG8YkEdTL5BZpDy0eHV5h_yC9uEX-dxrcsDcAFCNiVa4tGCnFb2Pzey67xK25s4n2I7uObLtCX2EjV4Gmx3qq9jPR1zwjNFCrPGqdgdpKR8u9HYToGkp2LAv68ve8-RxkWaFcjWAfCnUqyJhKtA335E9mhSP6Dsdn-URep9e1EValFuf4vijuJAuOWfNMaRqsbw36LWKQ4XYjQZFcpy7-3pf6a3tjRldDDCLCCnnDw1HS1iL1aBe8jScuAzas5wwRNs_8igvPeBogs-c-J-CtTRS8419_RaHQ");
            jwtService.readJWToken(requestReadJwt);
        } catch (FaultException e) {
            e.printStackTrace();
        }
     */


        Value createJwtValue = Value.create();
        createJwtValue.getFirstChild("registeredClaims").getFirstChild("sub").setValue("test");
        createJwtValue.getFirstChild("registeredClaims").getFirstChild("iss").setValue("cloudstorage@jvproject-289212.iam.gserviceaccount.com");
        createJwtValue.getFirstChild("registeredClaims").getFirstChild("scope").setValue("https://www.googleapis.com/auth/storage.objects.create");
        createJwtValue.getFirstChild("registeredClaims").getFirstChild("aud").setValue("https://oauth2.googleapis.com/token");
        createJwtValue.getFirstChild("registeredClaims").getFirstChild("exp").setValue(1612190938L);
        createJwtValue.getFirstChild("registeredClaims").getFirstChild("iat").setValue(1612190703L);
        Value v = jwtService.createJWToken(createJwtValue);
        System.out.println(v.getFirstChild("jwt").strValue());
       /* Value userClaim = Value.create();
        userClaim.getFirstChild("name").setValue("role");
        userClaim.getFirstChild("value").setValue("admin");
        createJwtValue.getChildren("userClaims").add(userClaim);
        Value jwtValue = null;
        try {
            jwtValue = jwtService.createJWToken(createJwtValue);
            Value valueDecode = jwtService.readJWToken(jwtValue);
            System.out.println(valueDecode.getChildren("userClaims").get(0).getFirstChild("name").strValue());
            System.out.println(valueDecode.getChildren("userClaims").get(0).getFirstChild("value").strValue());
        } catch (FaultException e) {
            e.printStackTrace();
        }*/

    }

}