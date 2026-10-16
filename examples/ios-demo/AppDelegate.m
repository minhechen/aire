#import <UIKit/UIKit.h>
#import "FavoriteStore.h"
#import "LoginService.h"
#import "PreviewStore.h"

@interface DemoViewController : UIViewController
@property(nonatomic, strong) FavoriteStore *favorites;
@property(nonatomic, strong) PreviewStore *preview;
@property(nonatomic, strong) LoginService *login;
@property(nonatomic, strong) UILabel *statusLabel;
@end

@implementation DemoViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.title = @"aire demo";
    self.favorites = [[FavoriteStore alloc] init];
    self.preview = [[PreviewStore alloc] init];
    self.login = [[LoginService alloc] init];

    UIStackView *stack = [[UIStackView alloc] init];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 20;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [stack.widthAnchor constraintEqualToConstant:260]
    ]];
    NSArray<NSString *> *keys = @[@"favorite.button", @"code.button", @"preview.button"];
    NSArray<NSString *> *actions = @[@"favoriteTapped:", @"requestCodeTapped:", @"previewTapped:"];
    for (NSUInteger index = 0; index < keys.count; index++) {
        UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
        [button setTitle:NSLocalizedString(keys[index], nil) forState:UIControlStateNormal];
        [button addTarget:self action:NSSelectorFromString(actions[index])
           forControlEvents:UIControlEventTouchUpInside];
        [stack addArrangedSubview:button];
    }
    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.numberOfLines = 0;
    [stack addArrangedSubview:self.statusLabel];
    // Restores the same persisted collection when the view is first loaded.
    self.statusLabel.text = [[self.favorites loadFavorites] componentsJoinedByString:@", "];
}

- (void)favoriteTapped:(id)sender {
    [self.favorites saveFavorite:@"Offline reverse engineering"];
    self.statusLabel.text = [[self.favorites loadFavorites] componentsJoinedByString:@", "];
}

- (void)requestCodeTapped:(id)sender {
    [self.login requestCode:@"15500000000"];
}

- (void)previewTapped:(id)sender {
    [self.preview saveFavorite:@"Temporary preview"];
}

@end

@interface DemoAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation DemoAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    DemoViewController *controller = [[DemoViewController alloc] init];
    self.window.rootViewController = [[UINavigationController alloc] initWithRootViewController:controller];
    [self.window makeKeyAndVisible];
    return YES;
}

@end
