"""Inspector-managed SecureCRT Bridge package.

The source directory retains its hyphenated name for backwards-compatible
SecureCRT script paths, while setuptools exposes it as
``allsre_inspector.securecrt_bridge``.
"""

from .service import SecureCRTBridgeService

__all__ = ["SecureCRTBridgeService"]
