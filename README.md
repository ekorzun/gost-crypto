# gost-crypto

http://gostcrypto.com

**!! IMPORTANT !!**

**This package is browser only, bacause of using Web Workers.**

## 1. Installation 

Add package through npm
```
npm install gost-crypto --save
```
Or through yarn:
```
yarn add gost-crypto
```

## 2. Setup

Make sure you have copied webworker script into your `public` (`dist` or `build` or `assets` etc) directory.

```
cp node_modules/gost-crypto/lib/cryptoEngineWorker.js public/gostEngineWorker.js
```

By default, worker will be loaded from root host `/`. If your assets serve from another host or path like `/frontend/assets` you have to add 
variable `window.__PUBLIC__URL__ = '/frontend/assets'`.

## 3. Usage

```
import crypto from 'gost-crypto'
// ...
```

## Original Description
---

Pure Javascript implementation of WebCrypto API interfaces and Public Key 
Infrastructure for GOST algorithms (Russian Cryptographic Standards)

Documentation, demonstartion, examples, references:

http://gostcrypto.com

Copyright (c) 2014-2016, Rudolf Nickolaev. 
All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

