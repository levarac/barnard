#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(BarnardIdentity, NSObject)

RCT_EXTERN_METHOD(signingPublicKey:(NSString *)eventCode
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sign:(NSString *)eventCode
                  bytesHex:(NSString *)bytesHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
