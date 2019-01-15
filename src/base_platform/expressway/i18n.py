"""
Helper module for python programs that need to access the system messages file.
Usage::

    from base_platform.expressway.i18n import translate
    print translate("banana")
    print translate("%d gnomes", 42)
"""

# Ignore TODOs                 pylint: disable=W0511
# Ignore invalid name          pylint: disable=C0103
# Ignore using global          pylint: disable=W0603

import gettext
import locale
import re
import os

DEFAULT_DOMAIN = 'messages'
DEFAULT_LOCALEDIR = '/tandberg/locale'
DEFAULT_LANGUAGE = 'en_US.utf8'

translations = None
existing_mos = None

system_tokens = {}
mcwebhelp_regex = re.compile(r'\[\[MCWEBHELP[:,]\s?\w+,\w+,\s?(.+?)\]\]')
html_regex = re.compile(r'<[^<]+?>')

def init(domain=DEFAULT_DOMAIN, localedir=DEFAULT_LOCALEDIR,
         language=DEFAULT_LANGUAGE):
    """
    Opens and reads the messages file.  This gets called once with the default
    arguments the first time you call :func:`translate`, but you can call it
    yourself if you want to use different options.
    """

    # We need to monkey patch locale.normalize so it doesn't mess with the case
    # of our language in gettext.find
    def passthrough_normalize(localename):
        """
        Returns localename unaltered.
        """
        return localename

    original_normalize = locale.normalize
    locale.normalize = passthrough_normalize

    # Load the translations
    global translations
    translations = gettext.translation(domain, localedir, [language],fallback=True)

    global existing_mos
    existing_mos = [domain]
    # Put locale.normalize back
    locale.normalize = original_normalize

    global system_tokens
    system_tokens = {"[[PRODUCT]]" : translations.ugettext("SYSTEM_TOKEN")}

    # oak only needs to be moved out
    system_tokens["[[CONTROL]]"] = translations.ugettext("C_SYSTEM_TOKEN")
    system_tokens["[[EXPRESSWAY]]"] = translations.ugettext("E_SYSTEM_TOKEN")

def check_for_new_mos(domain=DEFAULT_DOMAIN, localedir=DEFAULT_LOCALEDIR,
         language=DEFAULT_LANGUAGE):
    # We need to monkey patch locale.normalize so it doesn't mess with the case
    # of our language in gettext.find
    def passthrough_normalize(localename):
        """
        Returns localename unaltered.
        """
        return localename


    # Get the list of mo files which will form the domains used for creating
    # translations.
    path = "%s/%s" % (localedir,language)
    stdout_list = [filename.split(".")[0] for dirpath, dirnames, filenames in os.walk(path)
                   for filename in filenames if os.path.splitext(filename)[1] == ".mo"]

    global existing_mos

    # if blend has been removed regenerate full catalogue
    if len(set(existing_mos) - set(stdout_list)) > 0:
        init()

    original_normalize = locale.normalize
    locale.normalize = passthrough_normalize

    # get the domains not in the list
    domains = set(stdout_list) - set(existing_mos)
    for dom in domains:
        try:
            global translations
            try:
                translations._catalog.update(gettext.translation(dom, localedir, [language])._catalog)
            except AttributeError:
                translations = gettext.translation(dom, localedir, [language], fallback=True)
            existing_mos.append(dom)

        except IOError:
            pass

    # Put locale.normalize back
    locale.normalize = original_normalize

def translate(message, n=None):
    """
    Returns the translation of ``message``, or just returns ``message``
    unaltered if no translation exists.  If ``n`` is provided then the .plural
    form of the message is used, and ``n`` is substituted back into the
    translated string.
    """
    if translations is None:
        init()

    # check if new mo files exist and update catalogue if they do
    check_for_new_mos()

    if not message:
        return ""

    if n is None:
        ret = translations.ugettext(message)
    else:
        singular = message
        plural = singular + ".plural"
        ret = translations.ungettext(singular, plural, n) % n

    for token in system_tokens:
        ret = ret.replace(token, system_tokens[token])

    m = re.search(mcwebhelp_regex, ret)
    if m:
        replacement = translations.ugettext(m.group(1))
        ret = mcwebhelp_regex.sub(replacement, ret)
    ret = re.sub(r'(?:\<br\/\>)+', '\n', ret)
    ret = html_regex.sub(' ', ret)
    ret = re.sub(r' +', ' ', ret)
    return ret

_ = translate
