#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LoginService : NSObject
- (void)requestCode:(NSString *)phone;
@end

NS_ASSUME_NONNULL_END
