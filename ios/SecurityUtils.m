//
//  SecurityUtils.m
//
//  Created by julian on 13/03/2018.
//

NSString *const IV = @"AEE0715D0778A4E4";
NSString *const KEY =  @"9336365521W5F092BB5909E8E033BC69";


#import "SecurityUtils.h"


@implementation SecurityUtils


+ (NSString *)encrypt:(NSString *)plainText error:(NSError **)error {
    NSMutableData *result =  [SecurityUtils doAES:[plainText dataUsingEncoding:NSUTF8StringEncoding] context: kCCEncrypt error:error];
    return [result base64EncodedStringWithOptions:0];
}


+ (NSString *)decrypt:(NSString *)encryptedBase64String error:(NSError **)error {
    NSData *dataToDecrypt = [[NSData alloc] initWithBase64EncodedString:encryptedBase64String options:0];
    NSMutableData *result = [SecurityUtils doAES:dataToDecrypt context: kCCDecrypt error:error];
    return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    
}

+ (NSMutableData *)doAES:(NSData *)dataIn context:(CCOperation)kCCEncrypt_or_kCCDecrypt error:(NSError **)error {
        CCCryptorStatus ccStatus   = kCCSuccess;
        size_t          cryptBytes = 0;
        NSMutableData  *dataOut    = [NSMutableData dataWithLength:dataIn.length + kCCBlockSizeBlowfish];
        NSData *key =[KEY dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [IV dataUsingEncoding:NSUTF8StringEncoding];
        
        ccStatus = CCCrypt( kCCEncrypt_or_kCCDecrypt,
                           kCCAlgorithmAES,
                           kCCOptionPKCS7Padding,
                           key.bytes,
                           key.length,
                           (iv)?nil:iv.bytes,
                           dataIn.bytes,
                           dataIn.length,
                           dataOut.mutableBytes,
                           dataOut.length,
                           &cryptBytes);
        
        if (ccStatus == kCCSuccess) {
            dataOut.length = cryptBytes;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:@"kEncryptionError"
                                             code:ccStatus
                                         userInfo:nil];
            }
            dataOut = nil;
        }
        
        return dataOut;
}


@end
