package probe

import "errors"

// ErrUnsupportedLink marks a link whose frames do not start with an ethernet
// header at the tc hooks, such as tun, wireguard or xfrm devices, the
// programs would read their IP header as ethernet
var ErrUnsupportedLink = errors.New("link frames carry no ethernet header")
