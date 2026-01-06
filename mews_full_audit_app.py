==> Downloading cache...
==> Cloning from https://github.com/SamHMews/mews-audit-backend
==> Checking out commit 210ff3bc23be369c1482402ed076fec20df23973 in branch main
==> Downloaded 121MB in 4s. Extraction took 2s.
==> Installing Python version 3.13.4...
==> Using Python version 3.13.4 (default)
==> Docs on specifying a Python version: https://render.com/docs/python-version
==> Using Poetry version 2.1.3 (default)
==> Docs on specifying a Poetry version: https://render.com/docs/poetry-version
==> Running build command 'pip install -r requirements.txt'...
Collecting Flask==3.0.3 (from -r requirements.txt (line 1))
  Using cached flask-3.0.3-py3-none-any.whl.metadata (3.2 kB)
Collecting Werkzeug==3.0.3 (from -r requirements.txt (line 2))
  Using cached werkzeug-3.0.3-py3-none-any.whl.metadata (3.7 kB)
Collecting gunicorn==22.0.0 (from -r requirements.txt (line 3))
  Using cached gunicorn-22.0.0-py3-none-any.whl.metadata (4.4 kB)
Collecting requests==2.32.3 (from -r requirements.txt (line 4))
  Using cached requests-2.32.3-py3-none-any.whl.metadata (4.6 kB)
Collecting Flask-Limiter==3.8.0 (from -r requirements.txt (line 5))
  Using cached Flask_Limiter-3.8.0-py3-none-any.whl.metadata (6.1 kB)
Collecting flask-cors==4.0.1 (from -r requirements.txt (line 6))
  Using cached Flask_Cors-4.0.1-py2.py3-none-any.whl.metadata (5.5 kB)
Collecting reportlab==4.2.2 (from -r requirements.txt (line 7))
  Using cached reportlab-4.2.2-py3-none-any.whl.metadata (1.4 kB)
Collecting svglib==1.5.1 (from -r requirements.txt (line 8))
  Using cached svglib-1.5.1-py3-none-any.whl
Collecting lxml==5.2.2 (from -r requirements.txt (line 9))
  Using cached lxml-5.2.2-cp313-cp313-linux_x86_64.whl
Collecting tinycss2==1.3.0 (from -r requirements.txt (line 10))
  Using cached tinycss2-1.3.0-py3-none-any.whl.metadata (3.0 kB)
Collecting cssselect2==0.7.0 (from -r requirements.txt (line 11))
  Using cached cssselect2-0.7.0-py3-none-any.whl.metadata (2.9 kB)
Collecting Jinja2>=3.1.2 (from Flask==3.0.3->-r requirements.txt (line 1))
  Using cached jinja2-3.1.6-py3-none-any.whl.metadata (2.9 kB)
Collecting itsdangerous>=2.1.2 (from Flask==3.0.3->-r requirements.txt (line 1))
  Using cached itsdangerous-2.2.0-py3-none-any.whl.metadata (1.9 kB)
Collecting click>=8.1.3 (from Flask==3.0.3->-r requirements.txt (line 1))
  Using cached click-8.3.1-py3-none-any.whl.metadata (2.6 kB)
Collecting blinker>=1.6.2 (from Flask==3.0.3->-r requirements.txt (line 1))
  Using cached blinker-1.9.0-py3-none-any.whl.metadata (1.6 kB)
Collecting MarkupSafe>=2.1.1 (from Werkzeug==3.0.3->-r requirements.txt (line 2))
  Using cached markupsafe-3.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl.metadata (2.7 kB)
Collecting packaging (from gunicorn==22.0.0->-r requirements.txt (line 3))
  Using cached packaging-25.0-py3-none-any.whl.metadata (3.3 kB)
Collecting charset-normalizer<4,>=2 (from requests==2.32.3->-r requirements.txt (line 4))
  Using cached charset_normalizer-3.4.4-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl.metadata (37 kB)
Collecting idna<4,>=2.5 (from requests==2.32.3->-r requirements.txt (line 4))
  Using cached idna-3.11-py3-none-any.whl.metadata (8.4 kB)
Collecting urllib3<3,>=1.21.1 (from requests==2.32.3->-r requirements.txt (line 4))
  Using cached urllib3-2.6.2-py3-none-any.whl.metadata (6.6 kB)
Collecting certifi>=2017.4.17 (from requests==2.32.3->-r requirements.txt (line 4))
  Using cached certifi-2026.1.4-py3-none-any.whl.metadata (2.5 kB)
Collecting limits>=3.13 (from Flask-Limiter==3.8.0->-r requirements.txt (line 5))
  Using cached limits-5.6.0-py3-none-any.whl.metadata (10 kB)
Collecting ordered-set<5,>4 (from Flask-Limiter==3.8.0->-r requirements.txt (line 5))
  Using cached ordered_set-4.1.0-py3-none-any.whl.metadata (5.3 kB)
Collecting rich<14,>=12 (from Flask-Limiter==3.8.0->-r requirements.txt (line 5))
  Using cached rich-13.9.4-py3-none-any.whl.metadata (18 kB)
Collecting typing-extensions>=4 (from Flask-Limiter==3.8.0->-r requirements.txt (line 5))
  Using cached typing_extensions-4.15.0-py3-none-any.whl.metadata (3.3 kB)
Collecting pillow>=9.0.0 (from reportlab==4.2.2->-r requirements.txt (line 7))
  Using cached pillow-12.1.0-cp313-cp313-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl.metadata (8.8 kB)
Collecting chardet (from reportlab==4.2.2->-r requirements.txt (line 7))
  Using cached chardet-5.2.0-py3-none-any.whl.metadata (3.4 kB)
Collecting webencodings>=0.4 (from tinycss2==1.3.0->-r requirements.txt (line 10))
  Using cached webencodings-0.5.1-py2.py3-none-any.whl.metadata (2.1 kB)
Collecting markdown-it-py>=2.2.0 (from rich<14,>=12->Flask-Limiter==3.8.0->-r requirements.txt (line 5))
  Using cached markdown_it_py-4.0.0-py3-none-any.whl.metadata (7.3 kB)
Collecting pygments<3.0.0,>=2.13.0 (from rich<14,>=12->Flask-Limiter==3.8.0->-r requirements.txt (line 5))
  Using cached pygments-2.19.2-py3-none-any.whl.metadata (2.5 kB)
Collecting deprecated>=1.2 (from limits>=3.13->Flask-Limiter==3.8.0->-r requirements.txt (line 5))
  Using cached deprecated-1.3.1-py2.py3-none-any.whl.metadata (5.9 kB)
Collecting wrapt<3,>=1.10 (from deprecated>=1.2->limits>=3.13->Flask-Limiter==3.8.0->-r requirements.txt (line 5))
  Using cached wrapt-2.0.1-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl.metadata (9.0 kB)
Collecting mdurl~=0.1 (from markdown-it-py>=2.2.0->rich<14,>=12->Flask-Limiter==3.8.0->-r requirements.txt (line 5))
  Using cached mdurl-0.1.2-py3-none-any.whl.metadata (1.6 kB)
Using cached flask-3.0.3-py3-none-any.whl (101 kB)
Using cached werkzeug-3.0.3-py3-none-any.whl (227 kB)
Using cached gunicorn-22.0.0-py3-none-any.whl (84 kB)
Using cached requests-2.32.3-py3-none-any.whl (64 kB)
Using cached Flask_Limiter-3.8.0-py3-none-any.whl (28 kB)
Using cached Flask_Cors-4.0.1-py2.py3-none-any.whl (14 kB)
Using cached reportlab-4.2.2-py3-none-any.whl (1.9 MB)
Using cached tinycss2-1.3.0-py3-none-any.whl (22 kB)
Using cached cssselect2-0.7.0-py3-none-any.whl (15 kB)
Using cached charset_normalizer-3.4.4-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl (153 kB)
Using cached idna-3.11-py3-none-any.whl (71 kB)
Using cached ordered_set-4.1.0-py3-none-any.whl (7.6 kB)
Using cached rich-13.9.4-py3-none-any.whl (242 kB)
Using cached pygments-2.19.2-py3-none-any.whl (1.2 MB)
Using cached urllib3-2.6.2-py3-none-any.whl (131 kB)
Using cached blinker-1.9.0-py3-none-any.whl (8.5 kB)
Using cached certifi-2026.1.4-py3-none-any.whl (152 kB)
Using cached click-8.3.1-py3-none-any.whl (108 kB)
Using cached itsdangerous-2.2.0-py3-none-any.whl (16 kB)
Using cached jinja2-3.1.6-py3-none-any.whl (134 kB)
Using cached limits-5.6.0-py3-none-any.whl (60 kB)
Using cached deprecated-1.3.1-py2.py3-none-any.whl (11 kB)
Using cached wrapt-2.0.1-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl (121 kB)
Using cached markdown_it_py-4.0.0-py3-none-any.whl (87 kB)
Using cached mdurl-0.1.2-py3-none-any.whl (10.0 kB)
Using cached markupsafe-3.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl (22 kB)
Using cached packaging-25.0-py3-none-any.whl (66 kB)
Using cached pillow-12.1.0-cp313-cp313-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl (7.0 MB)
Using cached typing_extensions-4.15.0-py3-none-any.whl (44 kB)
Using cached webencodings-0.5.1-py2.py3-none-any.whl (11 kB)
Using cached chardet-5.2.0-py3-none-any.whl (199 kB)
Installing collected packages: webencodings, wrapt, urllib3, typing-extensions, tinycss2, pygments, pillow, packaging, ordered-set, mdurl, MarkupSafe, lxml, itsdangerous, idna, click, charset-normalizer, chardet, certifi, blinker, Werkzeug, requests, reportlab, markdown-it-py, Jinja2, gunicorn, deprecated, cssselect2, svglib, rich, limits, Flask, Flask-Limiter, flask-cors
Successfully installed Flask-3.0.3 Flask-Limiter-3.8.0 Jinja2-3.1.6 MarkupSafe-3.0.3 Werkzeug-3.0.3 blinker-1.9.0 certifi-2026.1.4 chardet-5.2.0 charset-normalizer-3.4.4 click-8.3.1 cssselect2-0.7.0 deprecated-1.3.1 flask-cors-4.0.1 gunicorn-22.0.0 idna-3.11 itsdangerous-2.2.0 limits-5.6.0 lxml-5.2.2 markdown-it-py-4.0.0 mdurl-0.1.2 ordered-set-4.1.0 packaging-25.0 pillow-12.1.0 pygments-2.19.2 reportlab-4.2.2 requests-2.32.3 rich-13.9.4 svglib-1.5.1 tinycss2-1.3.0 typing-extensions-4.15.0 urllib3-2.6.2 webencodings-0.5.1 wrapt-2.0.1
[notice] A new release of pip is available: 25.1.1 -> 25.3
[notice] To update, run: pip install --upgrade pip
==> Uploading build...
==> Uploaded in 11.4s. Compression took 3.1s
==> Build successful 🎉
==> Setting WEB_CONCURRENCY=1 by default, based on available CPUs in the instance
==> Deploying...
==> Running 'gunicorn --timeout 120 --workers 1 mews_full_audit_app:app'
Traceback (most recent call last):
  File "/opt/render/project/src/.venv/bin/gunicorn", line 8, in <module>
    sys.exit(run())
             ~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/wsgiapp.py", line 67, in run
    WSGIApplication("%(prog)s [OPTIONS] [APP_MODULE]", prog=prog).run()
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/base.py", line 236, in run
    super().run()
    ~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/base.py", line 72, in run
    Arbiter(self).run()
    ~~~~~~~^^^^^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/arbiter.py", line 58, in __init__
    self.setup(app)
    ~~~~~~~~~~^^^^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/arbiter.py", line 118, in setup
    self.app.wsgi()
    ~~~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/base.py", line 67, in wsgi
    self.callable = self.load()
                    ~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/wsgiapp.py", line 58, in load
    return self.load_wsgiapp()
           ~~~~~~~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/wsgiapp.py", line 48, in load_wsgiapp
    return util.import_app(self.app_uri)
           ~~~~~~~~~~~~~~~^^^^^^^^^^^^^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/util.py", line 371, in import_app
    mod = importlib.import_module(module)
  File "/opt/render/project/python/Python-3.13.4/lib/python3.13/importlib/__init__.py", line 88, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<frozen importlib._bootstrap>", line 1387, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1360, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1331, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 935, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 1022, in exec_module
  File "<frozen importlib._bootstrap_external>", line 1160, in get_code
  File "<frozen importlib._bootstrap_external>", line 1090, in source_to_code
  File "<frozen importlib._bootstrap>", line 488, in _call_with_frames_removed
  File "/opt/render/project/src/mews_full_audit_app.py", line 1285
    _render_po_table("Payment Origin (last 90 days) — Failed / Cancelled", po_failed, err_po_failed, fallback_origins=po_charged)
IndentationError: unexpected indent
==> Exited with status 1
==> Common ways to troubleshoot your deploy: https://render.com/docs/troubleshooting-deploys
==> Running 'gunicorn --timeout 120 --workers 1 mews_full_audit_app:app'
Traceback (most recent call last):
  File "/opt/render/project/src/.venv/bin/gunicorn", line 8, in <module>
    sys.exit(run())
             ~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/wsgiapp.py", line 67, in run
    WSGIApplication("%(prog)s [OPTIONS] [APP_MODULE]", prog=prog).run()
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/base.py", line 236, in run
    super().run()
    ~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/base.py", line 72, in run
    Arbiter(self).run()
    ~~~~~~~^^^^^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/arbiter.py", line 58, in __init__
    self.setup(app)
    ~~~~~~~~~~^^^^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/arbiter.py", line 118, in setup
    self.app.wsgi()
    ~~~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/base.py", line 67, in wsgi
    self.callable = self.load()
                    ~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/wsgiapp.py", line 58, in load
    return self.load_wsgiapp()
           ~~~~~~~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/wsgiapp.py", line 48, in load_wsgiapp
    return util.import_app(self.app_uri)
           ~~~~~~~~~~~~~~~^^^^^^^^^^^^^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/util.py", line 371, in import_app
    mod = importlib.import_module(module)
  File "/opt/render/project/python/Python-3.13.4/lib/python3.13/importlib/__init__.py", line 88, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<frozen importlib._bootstrap>", line 1387, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1360, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1331, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 935, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 1022, in exec_module
  File "<frozen importlib._bootstrap_external>", line 1160, in get_code
  File "<frozen importlib._bootstrap_external>", line 1090, in source_to_code
  File "<frozen importlib._bootstrap>", line 488, in _call_with_frames_removed
  File "/opt/render/project/src/mews_full_audit_app.py", line 1285
    _render_po_table("Payment Origin (last 90 days) — Failed / Cancelled", po_failed, err_po_failed, fallback_origins=po_charged)
IndentationError: unexpected indent
==> Running 'gunicorn --timeout 120 --workers 1 mews_full_audit_app:app'
Traceback (most recent call last):
  File "/opt/render/project/src/.venv/bin/gunicorn", line 8, in <module>
    sys.exit(run())
             ~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/wsgiapp.py", line 67, in run
    WSGIApplication("%(prog)s [OPTIONS] [APP_MODULE]", prog=prog).run()
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/base.py", line 236, in run
    super().run()
    ~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/base.py", line 72, in run
    Arbiter(self).run()
    ~~~~~~~^^^^^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/arbiter.py", line 58, in __init__
    self.setup(app)
    ~~~~~~~~~~^^^^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/arbiter.py", line 118, in setup
    self.app.wsgi()
    ~~~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/base.py", line 67, in wsgi
    self.callable = self.load()
                    ~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/wsgiapp.py", line 58, in load
    return self.load_wsgiapp()
           ~~~~~~~~~~~~~~~~~^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/app/wsgiapp.py", line 48, in load_wsgiapp
    return util.import_app(self.app_uri)
           ~~~~~~~~~~~~~~~^^^^^^^^^^^^^^
  File "/opt/render/project/src/.venv/lib/python3.13/site-packages/gunicorn/util.py", line 371, in import_app
    mod = importlib.import_module(module)
  File "/opt/render/project/python/Python-3.13.4/lib/python3.13/importlib/__init__.py", line 88, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<frozen importlib._bootstrap>", line 1387, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1360, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1331, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 935, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 1022, in exec_module
  File "<frozen importlib._bootstrap_external>", line 1160, in get_code
  File "<frozen importlib._bootstrap_external>", line 1090, in source_to_code
  File "<frozen importlib._bootstrap>", line 488, in _call_with_frames_removed
  File "/opt/render/project/src/mews_full_audit_app.py", line 1285
    _render_po_table("Payment Origin (last 90 days) — Failed / Cancelled", po_failed, err_po_failed, fallback_origins=po_charged)
IndentationError: unexpected indent
