"""Scores images with Aletheia's pretrained ALASKA2 EfficientNet-B0 detectors.
Usage: ALETHEIA=DIR score_aletheia.py MODEL OUT.npy IMAGE...   (MODEL: juniw, jmipod, nsf5, steghide)
Writes each image's probability of stego, in argument order."""
import os, sys
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
A = os.environ["ALETHEIA"]  # a clone of github.com/daniellerch/aletheia, with its models
sys.path.insert(0, A)
import numpy as np
from aletheialib.models import NN
model, out, files = sys.argv[1], sys.argv[2], sys.argv[3:]
nn = NN("effnetb0", model_name=f"effnetb0-A-alaska2-{model}", shape=(512, 512, 3), inference=True)
nn.load_model(f"{A}/aletheia-models/effnetb0-A-alaska2-{model}.h5", quiet=True)
np.save(out, nn.predict(files, batch=16, verbose=0))
