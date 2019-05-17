### AES Cross-encryption ANDROID and IOS

A real example of AES encrypt and decrypt in ANDROID (java) and IOS (objc).

This discussion (https://stackoverflow.com/questions/40421146/aes-cbc-pkcs5padding-in-ios-objective-c-result-differs-from-android/56178213#56178213) originated the need for this project.
 


### 1. Tests codes

## ANDROID

 ```
 try {
        String encrypted = SecurityUtils.encrypt("My Secret Text");
        String decrypted = SecurityUtils.decrypt(encrypted);
        Log.e("encrypted", encrypted);
        Log.e("decrypted", decrypted);
    }catch(Exception ex){
        Log.e("AES", ex.getMessage());
    }
````

## ANDROID OUTPUT

```
2019-05-16 21:35:01.215 4920-4920/br.com.my.app E/encrypted: EJ41am5W1k6fA7ygFjTSEw==
2019-05-16 21:35:01.215 4920-4920/br.com.my.app E/decrypted: My Secret Text
````


## IOS

```
NSError *error;
NSString *encrypted = [SecurityUtils encrypt:@"My Secret Text" error:&error];
NSLog(@"encrypted: %@",encrypted);
NSLog(@"decrypted: %@",[SecurityUtils decrypt:encrypted error:&error]);
````

## IOS OUTPUT

```
2019-05-16 21:38:02.947043-0300 MyApp[63392:1590665] encrypted: EJ41am5W1k6fA7ygFjTSEw==
2019-05-16 21:38:02.947270-0300 MyApp[63392:1590665] decrypted: My Secret Text
````