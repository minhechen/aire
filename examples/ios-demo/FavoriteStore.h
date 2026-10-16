#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface FavoriteStore : NSObject
- (void)saveFavorite:(NSString *)title;
- (NSArray<NSString *> *)loadFavorites;
@end

NS_ASSUME_NONNULL_END
