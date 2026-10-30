"""SRNet (Boroumand, Chen and Fridrich, "Deep Residual Network for
Steganalysis of Digital Images", IEEE TIFS 14(5), 2019), layer for layer:
2 layers of type 1, 5 of type 2, 4 of type 3 and one of type 4, then a
fully connected layer. No pooling in the first seven layers, so the stego
noise isn't averaged away before the network learns where to look."""
import torch
import torch.nn as nn


def conv(cin, cout, stride=1):
    c = nn.Conv2d(cin, cout, 3, stride, 1, bias=True)
    nn.init.kaiming_normal_(c.weight, nonlinearity="relu")
    nn.init.constant_(c.bias, 0.2)  # as in the paper's code
    return c


class T1(nn.Sequential):
    def __init__(self, cin, cout):
        super().__init__(conv(cin, cout), nn.BatchNorm2d(cout), nn.ReLU(inplace=True))


class T2(nn.Module):
    def __init__(self, c):
        super().__init__()
        self.f = nn.Sequential(T1(c, c), conv(c, c), nn.BatchNorm2d(c))

    def forward(self, x):
        return x + self.f(x)


class T3(nn.Module):
    def __init__(self, cin, cout):
        super().__init__()
        self.f = nn.Sequential(T1(cin, cout), conv(cout, cout), nn.BatchNorm2d(cout),
                               nn.AvgPool2d(3, 2, 1))
        sc = nn.Conv2d(cin, cout, 1, 2, bias=True)
        nn.init.kaiming_normal_(sc.weight); nn.init.constant_(sc.bias, 0.2)
        self.s = nn.Sequential(sc, nn.BatchNorm2d(cout))

    def forward(self, x):
        return self.f(x) + self.s(x)


class SRNet(nn.Module):
    def __init__(self, cin=1):
        super().__init__()
        self.body = nn.Sequential(
            T1(cin, 64), T1(64, 16),
            *[T2(16) for _ in range(5)],
            T3(16, 16), T3(16, 64), T3(64, 128), T3(128, 256),
            T1(256, 512), conv(512, 512), nn.BatchNorm2d(512), nn.AdaptiveAvgPool2d(1))
        self.fc = nn.Linear(512, 2)
        nn.init.normal_(self.fc.weight, 0, 0.01); nn.init.constant_(self.fc.bias, 0)

    def forward(self, x):
        return self.fc(self.body(x).flatten(1))
