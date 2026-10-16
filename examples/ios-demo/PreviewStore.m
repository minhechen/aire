#import "PreviewStore.h"

@implementation PreviewStore {
    NSString *_lastPreview;
}

- (void)saveFavorite:(NSString *)title {
    _lastPreview = [title copy];
    NSLog(@"Preview only: %@", _lastPreview);
}

@end
