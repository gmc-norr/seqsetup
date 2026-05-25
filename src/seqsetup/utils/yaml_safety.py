"""YAML parsing helpers with billion-laughs / anchor-amplification protection.

PyYAML's ``safe_load`` neutralises the classic ``!!python/object`` RCE but
does NOT bound anchor expansion: a small (~1 KB) YAML document with deeply
nested ``&a [*b, *b, ...]`` aliases can expand to gigabytes during parse,
exhausting memory before any size cap on the output dict would fire.

Config YAML for SeqSetup (instruments, profiles, index kits) has no
legitimate need for YAML anchors or aliases — it's plain nested mappings
and sequences. Refusing inputs that use anchor or alias events eliminates
the attack class without sacrificing any real use case.

The refusal happens at the YAML *Composer* level (not by scanning the
source text) so that ``*`` and ``&`` characters inside string values stay
fine — only actual YAML anchor / alias events trigger ``UnsafeYAMLError``.

Usage::

    from ..utils.yaml_safety import safe_load_strict
    data = safe_load_strict(text)   # raises UnsafeYAMLError on anchors

"""

import yaml


class UnsafeYAMLError(ValueError):
    """Raised when YAML input contains constructs we refuse to parse.

    Subclass of ``ValueError`` so existing handlers that catch broad parse
    failures still see it; callers wanting to distinguish "malformed" from
    "rejected by policy" can catch this type specifically.
    """


class _NoAnchorSafeLoader(yaml.SafeLoader):
    """``SafeLoader`` that refuses anchor definitions and alias references.

    Overrides the Composer's ``compose_node`` to raise before the anchor
    is registered or the alias is resolved. Output identical to ``safe_load``
    for inputs that don't use these features.
    """

    def compose_node(self, parent, index):
        # An AliasEvent here means the input contains a ``*name`` reference.
        if self.check_event(yaml.events.AliasEvent):
            raise UnsafeYAMLError(
                "YAML aliases (*name) are not allowed in configuration files "
                "(billion-laughs / anchor-amplification defense)."
            )
        # All other events expose their ``anchor`` attribute; non-None means
        # the value carries an ``&name`` definition.
        event = self.peek_event()
        if event.anchor is not None:
            raise UnsafeYAMLError(
                "YAML anchors (&name) are not allowed in configuration files "
                "(billion-laughs / anchor-amplification defense)."
            )
        return super().compose_node(parent, index)


def safe_load_strict(text):
    """``yaml.safe_load`` with anchor/alias amplification refused.

    Raises :class:`UnsafeYAMLError` if anchors or aliases are present.
    Raises :class:`yaml.YAMLError` (the base PyYAML error) on regular
    parse failures — callers that already catch that keep working.
    """
    return yaml.load(text, Loader=_NoAnchorSafeLoader)
