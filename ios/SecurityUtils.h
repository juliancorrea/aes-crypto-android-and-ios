//
//  SecurityUtils.h
//
//  Created by julian on 13/03/2018.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>

NS_ASSUME_NONNULL_BEGIN

@interface SecurityUtils : NSObject

+ (NSString *)encrypt:(NSString *)plainText error:(NSError **)error;
+ (NSString *)decrypt:(NSString *)plainText error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
