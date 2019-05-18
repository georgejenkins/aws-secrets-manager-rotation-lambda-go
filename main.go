package main

import (
        "fmt"
        "log"
        "errors"
        "context"

        "github.com/aws/aws-lambda-go/lambda"
        "github.com/aws/aws-sdk-go/aws/awserr"
        "github.com/aws/aws-sdk-go/aws/session"
        "github.com/aws/aws-sdk-go/service/secretsmanager"
)

type SecretsManagerEvent struct {
        Token *string `json:"ClientRequestToken"`
        Arn *string `json:"SecretId"`
        Step *string `json:"Step"`
}

func main() {
        lambda.Start(HandleRequest)
}

func HandleRequest(context context.Context, req SecretsManagerEvent) error {
        // Setup the client
        svc := secretsmanager.New(session.New())

        // Make sure the version is staged correctly          
        desc, err := svc.DescribeSecret(
                &secretsmanager.DescribeSecretInput{
                        SecretId: req.Arn,
                },
        )

        if (nil != err) {
                return err
        }

        if (!*desc.RotationEnabled) {
                return fmt.Errorf("Secret %s is not enabled for rotation", *req.Arn)
        }
        
        if _, ok := desc.VersionIdsToStages[*req.Token]; !ok {
                return fmt.Errorf("Secret version %s has no stage for rotation of secret %s.", *req.Token, *req.Arn)
        }

        pending := false
        for _, value := range desc.VersionIdsToStages[*req.Token] { 
                if *value == "AWSCURRENT" {
                        return fmt.Errorf("Secret version %s already set as AWSCURRENT for secret %s.", *req.Token, *req.Arn)
                } else if *value == "AWSPENDING" {
                        pending = true 
                }
        }
        if false == pending {
                return fmt.Errorf("Secret version %s not set as AWSPENDING for rotation of secret %s.", *req.Token, *req.Arn)
        }

        switch *req.Step {
	case "createSecret":
                createSecret(svc, req.Arn, req.Token)
	case "setSecret":
                setSecret(svc, req.Arn, req.Token)
	case "testSecret":
                testSecret(svc, req.Arn, req.Token)
	case "finishSecret":
                finishSecret(svc, req.Arn, req.Token)
	default:
		return errors.New("Invalid step parameter")
        }
        
        return nil
}

//  This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
//  new secret and put it with the passed in token.
func createSecret(svc *secretsmanager.SecretsManager, Arn *string, Token *string) {
        // Make sure the current secret exists
        AWSCURRENT := "AWSCURRENT"
        _, err := svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
                SecretId: Arn,
                VersionStage: &AWSCURRENT,
        })
        if (nil != err) {
                panic(err)
        }

        // Now try to get the secret version, if that fails, put a new secret
        AWSPENDING := "AWSPENDING"
        _, err = svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
                SecretId: Arn,
                VersionId: Token,
                VersionStage: &AWSPENDING,
        })
        if (nil != err) {
                if awsErr, ok := err.(awserr.Error); ok {
                        if (awsErr.Code() != secretsmanager.ErrCodeResourceNotFoundException) {
                                panic(err)
                        }

                        // Generate a random password
                        excChars := "/@'\"\\"
                        pwd, err := svc.GetRandomPassword(&secretsmanager.GetRandomPasswordInput{
                                ExcludeCharacters: &excChars,
                        })  
                        if (nil != err) {
                               panic(err)  
                        } 

                        // Put the secret
                         _, err = svc.PutSecretValue(&secretsmanager.PutSecretValueInput {
                                SecretId: Arn,
                                ClientRequestToken: Token,
                                SecretString: pwd.RandomPassword,
                                VersionStages: []*string{ &AWSPENDING },
                        })  
                         if (nil != err) {
                                panic(err)  
                         }                  

                         log.Printf("createSecret: Successfully put secret for ARN %s and version %s.", *Arn, *Token)
                         
                } else {
                        panic(err)  
                }
        }
}

// This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
// credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.
func setSecret(svc *secretsmanager.SecretsManager, Arn *string, Token *string) {
        panic("setSecret not implemented")
}

// This method should validate that the AWSPENDING secret works in the service that the secret belongs to. For example, if the secret
// is a database credential, this method should validate that the user can login with the password in AWSPENDING and that the user has
// all of the expected permissions against the database.
func testSecret(svc *secretsmanager.SecretsManager, Arn *string, Token *string) {
        panic("testSecret not implemented")
}

func finishSecret(svc *secretsmanager.SecretsManager, Arn *string, Token *string) {
        // First describe the secret to get the current version
        sec, err := svc.DescribeSecret(&secretsmanager.DescribeSecretInput{
                SecretId: Arn,
        })
        if (nil != err) {
                panic(err)
        }

        var currentVersion string
        for key, _ := range sec.VersionIdsToStages { 
                if nil != sec.VersionIdsToStages[key] {
                        if key == *Token {
                                log.Printf("finishSecret: Version %s already marked as AWSCURRENT for %s", key, *Arn)
                                return
                        }
                        currentVersion = key
                        break
                }
        }

        AWSCURRENT := "AWSCURRENT"
        _, err = svc.UpdateSecretVersionStage(&secretsmanager.UpdateSecretVersionStageInput {
                SecretId: Arn, 
                VersionStage: &AWSCURRENT,
                MoveToVersionId: Token,
                RemoveFromVersionId: &currentVersion,
        })
        if (nil != err) {
                panic(err)
        }

        log.Printf("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s.", *Token, *Arn)
}