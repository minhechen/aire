#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// This unrelated receiver deliberately shares FavoriteStore's selector.
@interface PreviewStore : NSObject
- (void)saveFavorite:(NSString *)title;
@end

NS_ASSUME_NONNULL_END
