## estimate against exact, per-series differences of the store's samples

| node | hours | failed queries | rx exact IP | est/exact in | est/exact out | sampled packets in | 1/sqrt of them | sampled packets out | series max | query s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| baldy | 146 | 0 | 54050713 | 1.0003 | 0.9998 | 5406911 | 0.0004 | 6668118 | 780 | 24 |
| butte | 146 | 0 | 729623008 | 0.9998 | 1.0001 | 72948204 | 0.0001 | 73911219 | 9335 | 746 |
| cradle | 146 | 0 | 45158483 | 1.0000 | 0.9999 | 4516057 | 0.0005 | 5874937 | 398 | 11 |
| faber | 15 | 0 | 4027009 | 0.9969 | 0.9998 | 401460 | 0.0016 | 568148 | 433 | 1 |
| feldberg | 15 | 0 | 9468932 | 0.9995 | 1.0002 | 946415 | 0.0010 | 1074773 | 1522 | 3 |
| guadalupe | 15 | 0 | 4257917 | 0.9977 | 1.0014 | 424831 | 0.0015 | 569505 | 367 | 1 |
| highline | 146 | 0 | 89356607 | 0.9999 | 1.0000 | 8934527 | 0.0003 | 8735538 | 2067 | 49 |
| isere | 146 | 0 | 469587429 | 1.0000 | 1.0001 | 46960804 | 0.0001 | 46726535 | 245 | 5 |
| kebnekaise | 15 | 0 | 3417428 | 0.9999 | 1.0016 | 341711 | 0.0017 | 526319 | 287 | 0 |
| kongo | 40 | 0 | 13329656 | 1.0001 | 1.0000 | 1333082 | 0.0009 | 1709472 | 590 | 3 |
| lagern | 146 | 0 | 107324795 | 0.9998 | 1.0002 | 10729968 | 0.0003 | 12819868 | 355 | 14 |
| lantau | 146 | 0 | 53861517 | 1.0006 | 1.0005 | 5389260 | 0.0004 | 6035357 | 562 | 29 |
| montmartre | 15 | 0 | 53199133 | 0.9999 | 0.9998 | 5319240 | 0.0004 | 5465828 | 6529 | 12 |
| morasko | 146 | 0 | 43135980 | 1.0002 | 1.0005 | 4314610 | 0.0005 | 3008867 | 163 | 5 |
| namsan | 15 | 0 | 3936585 | 0.9988 | 1.0002 | 393168 | 0.0016 | 539648 | 402 | 1 |
| odake | 146 | 0 | 47420386 | 1.0001 | 0.9997 | 4742655 | 0.0005 | 5905487 | 353 | 25 |
| roraima | 146 | 0 | 81138674 | 1.0002 | 0.9997 | 8115416 | 0.0004 | 11899697 | 545 | 15 |
| rysy | 146 | 0 | 86287630 | 0.9997 | 1.0001 | 8626050 | 0.0003 | 12217253 | 3425 | 58 |
| timah | 146 | 0 | 71115734 | 0.9996 | 0.9997 | 7108445 | 0.0004 | 8440319 | 488 | 17 |
| toompea | 146 | 0 | 142506855 | 1.0002 | 1.0003 | 14254053 | 0.0003 | 15099280 | 3885 | 117 |
| walberla | 146 | 0 | 54332789 | 0.9997 | 0.9996 | 5431910 | 0.0004 | 7676889 | 278 | 5 |
| watchung | 15 | 0 | 6415844 | 1.0015 | 0.9999 | 642542 | 0.0012 | 676862 | 383 | 1 |

- est/exact in 0.9969 to 1.0015, out 0.9996 to 1.0016, largest deviation 0.31%
- sampled packets in 341711 to 72948204, 1/sqrt 0.012 to 0.171%
- sampled packets out 526319 to 73911219, 1/sqrt 0.012 to 0.138%
- difference over 1/sqrt, in: [('baldy', 0.8), ('butte', -1.7), ('cradle', 0.1), ('faber', -2.0), ('feldberg', -0.5), ('guadalupe', -1.5), ('highline', -0.4), ('isere', 0.3), ('kebnekaise', -0.1), ('kongo', 0.1), ('lagern', -0.8), ('lantau', 1.3), ('montmartre', -0.3), ('morasko', 0.5), ('namsan', -0.8), ('odake', 0.3), ('roraima', 0.5), ('rysy', -0.9), ('timah', -1.2), ('toompea', 0.9), ('walberla', -0.6), ('watchung', 1.2)]
- difference over 1/sqrt, out: [('baldy', -0.6), ('butte', 0.5), ('cradle', -0.1), ('faber', -0.2), ('feldberg', 0.2), ('guadalupe', 1.1), ('highline', 0.1), ('isere', 0.6), ('kebnekaise', 1.1), ('kongo', 0.0), ('lagern', 0.7), ('lantau', 1.2), ('montmartre', -0.5), ('morasko', 0.8), ('namsan', 0.1), ('odake', -0.7), ('roraima', -0.9), ('rysy', 0.2), ('timah', -0.8), ('toompea', 1.2), ('walberla', -1.2), ('watchung', -0.1)]
- root mean square of the 44 differences over 1/sqrt: 0.82
- hosts 22, hours 15 to 146, failed queries 0
- largest difference over 1/sqrt: in faber -1.952 (ratio 0.99692), out lantau 1.237 (ratio 1.00050)
- largest deviation: in faber -0.308%, out kebnekaise 0.156%
- hours by host: [15, 40, 146], hosts per count: [(15, 7), (40, 1), (146, 14)]
