#import "FavoriteStore.h"

static NSString *const FavoriteStorageKey = @"aire.favorites.v1";

@implementation FavoriteStore

- (void)saveFavorite:(NSString *)title {
    if (title.length == 0) {
        return;
    }
    NSMutableArray<NSString *> *favorites = [[self loadFavorites] mutableCopy];
    if (![favorites containsObject:title]) {
        [favorites addObject:title];
        [[NSUserDefaults standardUserDefaults] setObject:favorites forKey:FavoriteStorageKey];
    }
}

- (NSArray<NSString *> *)loadFavorites {
    NSArray<NSString *> *stored = [[NSUserDefaults standardUserDefaults] arrayForKey:FavoriteStorageKey];
    return stored ?: @[];
}

@end
