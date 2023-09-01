/*
Copyright Istio Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This file was generated using openssl by the gencerts.sh script
// and holds raw certificates for the webhook tests.

package testcerts // import "istio.io/istio/pkg/testcerts"

// CACert is a test cert for dynamic admission controller.
var CACert = []byte(`-----BEGIN CERTIFICATE-----
MIIC9DCCAdygAwIBAgIJAIFe3lWPaalKMA0GCSqGSIb3DQEBCwUAMA4xDDAKBgNV
BAMMA19jYTAgFw0xNzEyMjIxODA0MjRaGA8yMjkxMTAwNzE4MDQyNFowDjEMMAoG
A1UEAwwDX2NhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuBdxj+Hi
8h0TkId1f64TprLydwgzzLwXAs3wpmXz+BfnW1oMQPNyN7vojW6VzqJGGYLsc1OB
MgwObU/VeFNc6YUCmu6mfFJwoPfXMPnhmGuSwf/kjXomlejAYjxClU3UFVWQht54
xNLjTi2M1ZOnwNbECOhXC3Tw3G8mCtfanMAO0UXM5yObbPa8yauUpJKkpoxWA7Ed
qiuUD9qRxluFPqqw/z86V8ikmvnyjQE9960j+8StlAbRs82ArtnrhRgkDO0Smtf7
4QZsb/hA1KNMm73bOGS6+SVU+eH8FgVOzcTQYFRpRT3Mhi6dKZe9twIO8mpZK4wk
uygRxBM32Ag9QQIDAQABo1MwUTAdBgNVHQ4EFgQUc8tvoNNBHyIkoVV8XCXy63Ya
BEQwHwYDVR0jBBgwFoAUc8tvoNNBHyIkoVV8XCXy63YaBEQwDwYDVR0TAQH/BAUw
AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAVmaUkkYESfcfgnuPeZ4sTNs2nk2Y+Xpd
lxkMJhChb8YQtlCe4uiLvVe7er1sXcBLNCm/+2K9AT71gnxBSeS5mEOzWmCPErhy
RmYtSxeRyXAaUWVYLs/zMlBQ0Iz4dpY+FVVbMjIurelVwHF0NBk3VtU5U3lHyKdZ
j4C2rMjvTxmkyIcR1uBEeVvuGU8R70nZ1yfo3vDwmNGMcLwW+4QK+WcfwfjLXhLs
5550arfEYdTzYFMxY60HJT/LvbGrjxY0PQUWWDbPiRfsdRjOFduAbM0/EVRda/Oo
Fg72WnHeojDUhqEz4UyFZbnRJ4x6leQhnrIcVjWX4FFFktiO9rqqfw==
-----END CERTIFICATE-----`)

// BadCert is a abd x509 cert. Copied from crypto/x509/x509_test.go:1628
var BadCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIC1jCCAb6gAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAxMdRW1w
dHkgbmFtZSBjb25zdHJhaW50cyBpc3N1ZXIwHhcNMTMwMjAxMDAwMDAwWhcNMjAw
NTMwMTA0ODM4WjAhMR8wHQYDVQQDExZFbXB0eSBuYW1lIGNvbnN0cmFpbnRzMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwriElUIt3LCqmJObs+yDoWPD
F5IqgWk6moIobYjPfextZiYU6I3EfvAwoNxPDkN2WowcocUZMJbEeEq5ebBksFnx
f12gBxlIViIYwZAzu7aFvhDMyPKQI3C8CG0ZSC9ABZ1E3umdA3CEueNOmP/TChNq
Cl23+BG1Qb/PJkpAO+GfpWSVhTcV53Mf/cKvFHcjGNrxzdSoq9fyW7a6gfcGEQY0
LVkmwFWUfJ0wT8kaeLr0E0tozkIfo01KNWNzv6NcYP80QOBRDlApWu9ODmEVJHPD
blx4jzTQ3JLa+4DvBNOjVUOp+mgRmjiW0rLdrxwOxIqIOwNjweMCp/hgxX/hTQID
AQABoxEwDzANBgNVHR4EBjAEoAChADANBgkqhkiG9w0BAQsFAAOCAQEAWG+/zUMH
QhP8uNCtgSHyim/vh7wminwAvWgMKxlkLBFns6nZeQqsOV1lABY7U0Zuoqa1Z5nb
6L+iJa4ElREJOi/erLc9uLwBdDCAR0hUTKD7a6i4ooS39DTle87cUnj0MW1CUa6H
v5SsvpYW+1XleYJk/axQOOTcy4Es53dvnZsjXH0EA/QHnn7UV+JmlE3rtVxcYp6M
LYPmRhTioROA/drghicRkiu9hxdPyxkYS16M5g3Zj30jdm+k/6C6PeNtN9YmOOga
nCOSyFYfGhqOANYzpmuV+oIedAsPpIbfIzN8njYUs1zio+1IoI4o8ddM9sCbtPU8
o+WoY6IsCKXV/g==
-----END CERTIFICATE-----`)

// ServerKey is a test cert for dynamic admission controller.
var ServerKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqZ9WyVOdHCM3ToIKnYeo8EvbuZKglfhjee7yZ5ZQ4atboHmb
n9q0GhkE780ezNuyMVllr/5tha1iUjSGdCPip/l3GdfLVt719Iw5gsCPxRKHMnoJ
O5PcejMxzXFa4vRpIKF/fbJ/ZYDKpIJtOGlaIR4M4ZQb3661SftEO7DnqElfOo7D
kQ+9n1mg1FPUCo0OUZydJ55ezzDYhrPD6ry12qu+FQnrJt8WGNghEv9qwZ8cz8Wv
Xcj9RUgossCID1n4vsWKL3nks9LHhGcVnIoCUdqWjxkk2YvmcOIt9Ny5TKOx8VoK
wGpToMuZXxgzbyFdnzDit7tX3SteR2QFONq5DwIDAQABAoIBABmW50HiMl6PVYWr
iqxvTeZKm3BolX9qhJ9dlAZaoAMblewkzHyWQvt48My4lj/zmPNm+DdP2/gBy0Z5
lBsrWsNamEQ20P9fDZ4CFZ8LK+VgQTM1Q/VP/kAVPxsuUbbRhpacpp4w8pU+k9Oz
tYSAKE+8t9bEQFxDgCgUFxwmORyjDhyMxGO4hXq4vHR7SA8XGx4VRbr/KS4vbAR5
uvSX54MzU8UvP/y3G/8sCFRHp3+rWbwjAKXWCDO1paWxLMRM5vOs3wX1iowiaoWb
5rMtwyJsrEFm7HXIyGvdZnEHug9U5uMs86pC7Z8XDtFp5MA1CqD4IO5o8kzcbYbs
nJgUafECgYEA22HW2NPYQ5M3W8pXzYbuabfCtU0yYJPmwX652LO9mH1lM4KNxWsP
tpj2jcAMMPovBp6JapClVHFpAYk71ZmlkU2tV3F+fDJoqf9m5rU8iBuhQaBgwZaU
UqqQJDTkH+NeE3veRq73gR03qHwUa8lo5JQsVnmkxYdcmArsMSMPCCcCgYEAxe9G
JYCuoRZN16Meu8CrjtioETj8AMk3i64OzY83WcTgPY3tZanP7JtaONJDrgCjcnX8
rqDlq/EBN+fpQIUlL4ZUvi2XI5Z99TrimxtIcjTHaaUGe7zWU2ozAsYNLnkrxcMJ
MgCnns5WjVFMe2QdOaG+qpMfYfJpweCLufeusNkCgYEAmjGfX5EubPiZLUQACK4w
/k8xZFrY8LajtxaKK3zR4s8oBVdarAp+5dmHWcRFDVubF+zwKt11xu9bXcAGNTCk
BYfyMQbNXx/THsErozZ5UDUTV1wRBZ//qkbFvx0Jxjv50Hn8lfO+dJqDl0F23PeY
aSiYLUOcg1WLyDXNIxBALXsCgYBHkQw74xtBA1+B6GjkWfWt4IhkMcZsQlTjHDwd
9vp8asLpfrenWo7jbghhIyV1dKWkbSS/v01LrghSvneH7JxVYqyhVrqfE3rXgEMO
8f5vzMWNXS3K76xO3Mc06Yc6lnVNPAfHHJV+xfxlfE+7DafDfsgBxNBECfJTN21O
AFAZgQKBgQDRRC9Coel3Sm3jHwug3Pf1ziZg6BEwaNS6pSRqbcD9b66R298m/BHM
DYyKQ0uRkAvNVAT2WD87ZiK8IGgn+U7qWc+LlmvVVPJRiKbuxdjtGeH+2PFc9uFD
5QyMqlncVzkf3N4rNB6p83Yy5gEJLlfVXFKngu0MiH2J2NM7gqlonw==
-----END RSA PRIVATE KEY-----`)

// ServerCert is a test cert for dynamic admission controller.
var ServerCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDATCCAemgAwIBAgIJAIaY2+s9cKkgMA0GCSqGSIb3DQEBCwUAMA4xDDAKBgNV
BAMMA19jYTAgFw0xNzEyMjIxODA0MjRaGA8yMjkxMTAwNzE4MDQyNFowEjEQMA4G
A1UEAwwHX3NlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKmf
VslTnRwjN06CCp2HqPBL27mSoJX4Y3nu8meWUOGrW6B5m5/atBoZBO/NHszbsjFZ
Za/+bYWtYlI0hnQj4qf5dxnXy1be9fSMOYLAj8UShzJ6CTuT3HozMc1xWuL0aSCh
f32yf2WAyqSCbThpWiEeDOGUG9+utUn7RDuw56hJXzqOw5EPvZ9ZoNRT1AqNDlGc
nSeeXs8w2Iazw+q8tdqrvhUJ6ybfFhjYIRL/asGfHM/Fr13I/UVIKLLAiA9Z+L7F
ii955LPSx4RnFZyKAlHalo8ZJNmL5nDiLfTcuUyjsfFaCsBqU6DLmV8YM28hXZ8w
4re7V90rXkdkBTjauQ8CAwEAAaNcMFowCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAw
HQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMCEGA1UdEQQaMBiHBH8AAAGH
EAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZIhvcNAQELBQADggEBAD7aRhLfs4HlqE3E
AaV3WSGFq/m97PsoqQpKTYJ8kAXPE7cd0Pgh1A6Vm/NXIMNw3vSpLDOLy0Y6Ggbb
78bw3YeZuRkY5fEXmFf70248oxv+2MbIuJ0n1cU0hHOtHw6+BCC1q4yR5/iJ7YEX
jRbUacqhn9IxH9O8Bs7ntv6NaoHjUfskEiGyl1UZSAsFsd/Cp2Qu4Jmm0DHsvd+S
9oIO+EILiCvnGwcYfH4UFmNCx6S7JVOuNaFdgHUuo5dNDMj0hlt9krk3XfcCQ/YQ
K9pLL7WMDV5tvu437+UWUn0yZv6LkxcE33smqcHumrhwRtEfqAUbM1FHVteFZDCp
p3vBDAM=
-----END CERTIFICATE-----`)

// RotatedKey is a test cert for dynamic admission controller.
var RotatedKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3Tr24CaBegyfkdDGWckqMHEWvpJBThjXlMz/FKcg1bgq57OD
oNHXN4dcyPCHWWEY3Eo3YG1es4pqTkvzK0+1JoY6/K88Lu1ePj5PeSFuWfPWi1BW
9oyWJW+AAzqqGkZmSo4z26N+E7N8ht5bTBMNVD3jqz9+MaqCTVmQ6dAgdFKH07wd
XWh6kKoh2g9bgBKB+qWrezmVRb31i93sM1pJos35cUmIbWgiSQYuSXEInitejcGZ
cBjqRy61SiZB7nbmMoew0G0aGXe20Wx+QiyJjbt9XNUm0IvjAJ1SSiPqfFQ4F+tx
K4q3xAwp1smyiMv57RNC2ny8YMntZYgQDDkhBQIDAQABAoIBAQDZHK396yw0WEEd
vFN8+CRUaBfXLPe0KkMgAFLxtNdPhy9sNsueP3HESC7x8MQUHmtkfd1837kJ4HRV
pMnfnpj8Vs17AIrCzycnVMVv7jQ7SUcrb8v4qJ4N3TA3exJHOQHYd1hDXF81/Hbg
cUYOEcCKBTby8BvrqBe6y4ShQiUnoaeeM5j9x32+QB652/9PMuZJ9xfwyoEBjoVA
cccp+u3oBX864ztaG9Gn0wbgRVeafsPfuAOUmShykohV1mVJddiA0wayxGi0TmoK
dwrltdToI7BmpmmTLc59O44JFGwO67aJQHsrHBjEnpWlxFDwbfZuf93FgdFUFFjr
tVx2dPF9AoGBAPkIaUYxMSW78MD9862eJlGS6F/SBfPLTve3l9M+UFnEsWapNz+V
anlupaBtlfRJxLDzjheMVZTv/TaFIrrMdN/xc/NoYj6lw5RV8PEfKPB0FjSAqSEl
iVOA5q4kuI1xEeV7xLE4uJUF3wdoHz9cSmjrXDVZXq/KsaInABlAl1xjAoGBAONr
bgFUlQ+fbsGNjeefrIXBSU93cDo5tkd4+lefrmUVTwCo5V/AvMMQi88gV/sz6qCJ
gR0hXOqdQyn++cuqfMTDj4lediDGFEPho+n4ToIvkA020NQ05cKxcmn/6Ei+P9pk
v+zoT9RiVnkBje2n/KU2d/PEL9Nl4gvvAgPLt8V3AoGAZ6JZdQ15n3Nj0FyecKz0
01Oogl+7fGYqGap8cztmYsUY8lkPFdXPNnOWV3njQoMEaIMiqagL4Wwx2uNyvXvi
U2N+1lelMt720h8loqJN/irBJt44BARD7s0gsm2zo6DfSrnD8+Bf6BxGYSWyg0Kb
8KepesYTQmK+o3VJdDjOBHMCgYAIxbwYkQqu75d2H9+5b49YGXyadCEAHfnKCACg
IKi5fXjurZUrfGPLonfCJZ0/M2F5j9RLK15KLobIt+0qzgjCDkkbI2mrGfjuJWYN
QGbG3s7Ps62age/a8r1XGWf8ZlpQMlK08MEjkCeFw2mWIUS9mrxFyuuNXAC8NRv+
yXztQQKBgQDWTFFQdeYfuiKHrNmgOmLVuk1WhAaDgsdK8RrnNZgJX9bd7n7bm7No
GheN946AYsFge4DX7o0UXXJ3h5hTFn/hSWASI54cO6WyWNEiaP5HRlZqK7Jfej7L
mz+dlU3j/BY19RLmYeg4jFV4W66CnkDqpneOJs5WdmFFoWnHn7gRBw==
-----END RSA PRIVATE KEY-----`)

// RotatedCert is a test cert for dynamic admission controller.
var RotatedCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDATCCAemgAwIBAgIJAJwGb32Zn8sDMA0GCSqGSIb3DQEBCwUAMA4xDDAKBgNV
BAMMA19jYTAgFw0xODAzMTYxNzI0NDJaGA8yMjkxMTIzMDE3MjQ0MlowEjEQMA4G
A1UEAwwHX3NlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN06
9uAmgXoMn5HQxlnJKjBxFr6SQU4Y15TM/xSnINW4Kuezg6DR1zeHXMjwh1lhGNxK
N2BtXrOKak5L8ytPtSaGOvyvPC7tXj4+T3khblnz1otQVvaMliVvgAM6qhpGZkqO
M9ujfhOzfIbeW0wTDVQ946s/fjGqgk1ZkOnQIHRSh9O8HV1oepCqIdoPW4ASgfql
q3s5lUW99Yvd7DNaSaLN+XFJiG1oIkkGLklxCJ4rXo3BmXAY6kcutUomQe525jKH
sNBtGhl3ttFsfkIsiY27fVzVJtCL4wCdUkoj6nxUOBfrcSuKt8QMKdbJsojL+e0T
Qtp8vGDJ7WWIEAw5IQUCAwEAAaNcMFowCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAw
HQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMCEGA1UdEQQaMBiHBH8AAAGH
EAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZIhvcNAQELBQADggEBACbBlWo/pY/OIJaW
RwkfSRVzEIWpHt5OF6p93xfyy4/zVwwhH1AQB7Euji8vOaVNOpMfGYLNH3KIRReC
CIvGEH4yZDbpiH2cOshqMCuV1CMRUTdl4mq6M0PtGm6b8OG3uIFTLIR973LBWOl5
wCR1yrefT1NHuIScGaBXUGAV4JAx37pfg84hDD73T2j1TDD3Lrmsb9WCP+L26TG6
ICN61cIhgz8wChQpF8/fFAI5Fjbjrz5C1Xw/EUHLf/TTn/7Yfp2BHsGm126Et+k+
+MLBzBfrHKwPaGqDvNHUDrI6c3GI0Qp7jW93FbL5ul8JQ+AowoMF2dIEbN9qQEVP
ZOQ5UvU=
-----END CERTIFICATE-----`)

// ExpiredServerCert is a test expired cert for testing certificate renewal upon expiry.
var ExpiredServerCert = []byte(`-----BEGIN CERTIFICATE-----
MIIF5TCCA82gAwIBAgIUEooicnB1HsRaXq2wqC7XwNiTZ4cwDQYJKoZIhvcNAQEL
BQAwgYExCzAJBgNVBAYTAklOMQ4wDAYDVQQIDAVkdW1teTEOMAwGA1UEBwwFZHVt
bXkxDjAMBgNVBAoMBWR1bW15MQ4wDAYDVQQLDAVkdW1teTESMBAGA1UEAwwJZHVt
bXkuc3ZjMR4wHAYJKoZIhvcNAQkBFg9kdW1teUBkdW1teS5jb20wHhcNMTAwMTAx
MTAxMTE1WhcNMTAwMTA3MTAxMTE1WjCBgTELMAkGA1UEBhMCSU4xDjAMBgNVBAgM
BWR1bW15MQ4wDAYDVQQHDAVkdW1teTEOMAwGA1UECgwFZHVtbXkxDjAMBgNVBAsM
BWR1bW15MRIwEAYDVQQDDAlkdW1teS5zdmMxHjAcBgkqhkiG9w0BCQEWD2R1bW15
QGR1bW15LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALNhHFbW
yQYipvEhYOJ7Dook+8rSfRY7lmLcdURWdOfY/s5U6kBDRqtTvl25zrivwNoLtBIo
sYJFWchYEbv3k3457yfxawyuNfpwANv60bH7Hm9/ViBgqI5yrgB9Ly2pMDIGUjs2
1nJBSABGlZKcxRHhVKauv35DYG9hRa/C1AoIUsCziZHLggr9+eZ1CdmHTuKekWVt
9nriO02MXemKWfCZaRhPADnHf8oPw/rP+R/FrG6JF3JS9EVINQC8c9q0SyWbuwxg
4u9k9DKk/joZ0cbqlOS74Wvk2GFigIF9uuOhZdHzF/+IYH4ZNM0AFGVoKn+QwFG8
5kJyW6NsHIn5fOLyrT2rXXT/FJXr/lIJ//hzybIjHBfH4hB8uWvMLN2vrqT71yR6
dfQxqrTJcxJbidjA5LF0ABOQaJ0ja+OrL3LHofY1f9fXzUWV+Bx6NIvNlZwIxL4G
uhxQluxfQrmnjHy1yXW4PWTCc3fYT+aaz6q7yLN5VAEfl3Gg3mTfTPgyhuoL+Wn9
gOp5RMOzFvdxzD9ZjRg1dxC36Y5vCfzVC8tRjmIvoOKktv6TGRpbJvzvNeDWuPlP
00s4xPn9UXuPbCN6Cxsl3qWDE2NonH215DOy1NRiwsfmZg01JAljFTwTWjI2HjBa
fjXn/3pm4UA4xGB2C1Hq74+ZLF2U9M9IUkrBAgMBAAGjUzBRMB0GA1UdDgQWBBSk
ODcp+TNg5RNIJymjSMqYRamcwTAfBgNVHSMEGDAWgBSkODcp+TNg5RNIJymjSMqY
RamcwTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQA67VC0DDSb
EIJfZp2fM8uv39AkuN5Oa6cBVjtZdd9fE7ZUfR+53Wi0C/XZHgrt/ISKj0nY47X/
DkIaFuw1DbYTmg7hzpZZDUx4GATyRGUEJuZAj1ggr0u6AejOPWt52myFiuJBjQBw
Fde7XVlanStc+hJddFStnzGkEpyhjwtHy/hc2O9M6xlEDfN2M+/78YaC4D0wiVbQ
WRghpWLYaZ7sVmaOttpywxkCaaUaoB1x8/JLfMuEUWSrGAkd1mp0XZstRvGavslX
a8okRAx6XGDL4mmaXANwM63L5buRTnYoEla/0jYfYlgLnwee8yxElSfVJtXFaCJ3
GelAuOYQVqc7+cQoZgoEzjoZOr2YHue7MHR4g7P4t+Vl6CsuuPfv5a5RZVFKk/PK
BOgTUnfENTnuV730Gibh6cVTddAHxGQ3Wh0pjDPGOTB5QI85GxDBJcYEm0wdYqeq
eP/FFnS7G+tK4b+iKp6cAvNjKx2z3lVsHAQ39SSJK8Eg9M8Jj63K0wM0YD8KYI5R
8QfXhYIx1LnUGQ5M6BrLAgAOj/5bp4m60QqPEJIet1/6ByhqTq54fp+8twZO8uj7
CuHtHlYj72FMF/Q76Q9gyrDfC6Bt3FJyPTyCSKAXlv42g1NJ3GhEIWjrXHJPxfrh
8da8wNayiQo+u6TMKIsh9JFLMyNBxo+gyw==
-----END CERTIFICATE-----`)
