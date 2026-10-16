#import "LoginService.h"

@implementation LoginService

- (void)requestCode:(NSString *)phone {
    if (phone.length == 0) {
        return;
    }
    // Reserved .invalid domain: this educational sample has no real backend.
    NSURL *url = [NSURL URLWithString:@"https://api.aire-demo.invalid/v1/auth/code"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    request.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{@"phone": phone, @"purpose": @"login"}
                                                     options:0 error:nil];
    NSURLSessionDataTask *task = [[NSURLSession sharedSession]
        dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (error != nil) {
                NSLog(@"Code request failed: %@", error.localizedDescription);
                return;
            }
            NSLog(@"Code request finished: %lu bytes", (unsigned long)data.length);
        }];
    [task resume];
}

@end
