# mini_s3

mini_s3 is a simple s3 client API for erlang. This is used by the Chef
Server which can be found at https://github.com/chef/chef-server

# DEVELOPMENT

To build and test mini_s3, run:

    make all

This project uses eunit for testing. Please consider adding a unit
test when submitting a new feature or bug fix.

## Signing Your Commits

This project utilizes a Developer Certificate of Origin (DCO) to
ensure that each commit was written by the author or that the author
has the appropriate rights necessary to contribute the change.  The
project utilizes [Developer Certificate of Origin, Version 1.1](http://developercertificate.org/)

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Each commit must include a DCO which looks like this

`Signed-off-by: Joe Smith <joe.smith@email.com>`

The project requires that the name used is your real name. Neither
anonymous contributors nor those utilizing pseudonyms will be
accepted.

Git makes it easy to add this line to your commit messages.

1. Make sure the `user.name` and `user.email` are set in your git configs.
2. Use `-s` or `--signoff` to add the Signed-off-by line to the end of the commit message.

# LICENSE

Copyright 2011-2016 Chef Software, Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License.  You may
obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.  See the License for the specific language governing
permissions and limitations under the License.
