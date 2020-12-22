"""
<Program Name>
  fetcher.py

<Author>
  Teodora Sechkova <tsechkova@vmware.com>

<Started>
  December 14, 2020

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provides an interface for network IO abstraction.
"""

import abc
import requests
import six
import logging
import time

import urllib3.exceptions
import tuf.exceptions
import tuf.settings

logger = logging.getLogger(__name__)


class FetcherInterface():
  """
  <Purpose>
  Defines an interface for abstract network download which can be implemented
  for a variety of network libraries and configurations.
  """
  __metaclass__ = abc.ABCMeta


  @abc.abstractmethod
  def fetch(self, url, required_length):
    """
    <Purpose>
      Fetches the contents of HTTP/HTTPS url from a remote server up to
      required_length and returns a bytes iterator.

    <Arguments>
      url:
        A URL string that represents the location of the file.

      required_length:
        An integer value representing the length of the file in bytes.

    <Exceptions>
      tuf.exceptions.SlowRetrievalError, if a timeout occurs while receiving
      data from a server

    <Returns>
      A bytes iterator
    """
    raise NotImplementedError # pragma: no cover



class RequestsFetcher(FetcherInterface):
  """
  <Purpose>
    A concrete implementation of FetcherInterface based on the Requests
    library.
  """

  def __init__(self):
    # From http://docs.python-requests.org/en/master/user/advanced/#session-objects:
    #
    # "The Session object allows you to persist certain parameters across requests.
    # It also persists cookies across all requests made from the Session instance,
    # and will use urllib3's connection pooling. So if you're making several
    # requests to the same host, the underlying TCP connection will be reused,
    # which can result in a significant performance increase (see HTTP persistent
    # connection)."
    #
    # NOTE: We use a separate requests.Session per scheme+hostname combination, in
    # order to reuse connections to the same hostname to improve efficiency, but
    # avoiding sharing state between different hosts-scheme combinations to
    # minimize subtle security issues. Some cookies may not be HTTP-safe.
    self._sessions = {}


  def fetch(self, url, required_length):
    # Get a customized session for each new schema+hostname combination.
    session = self._get_session(url)

    # Get the requests.Response object for this URL.
    #
    # Defer downloading the response body with stream=True.
    # Always set the timeout. This timeout value is interpreted by requests as:
    #  - connect timeout (max delay before first byte is received)
    #  - read (gap) timeout (max delay between bytes received)
    with session.get(url, stream=True,
        timeout=tuf.settings.SOCKET_TIMEOUT) as response:

      # Check response status.
      response.raise_for_status()

      try:
        bytes_received = 0
        while True:
          # We download a fixed chunk of data in every round. This is so that we
          # can defend against slow retrieval attacks. Furthermore, we do not wish
          # to download an extremely large file in one shot.
          # Before beginning the round, sleep (if set) for a short amount of time
          # so that the CPU is not hogged in the while loop.
          if tuf.settings.SLEEP_BEFORE_ROUND:
            time.sleep(tuf.settings.SLEEP_BEFORE_ROUND)

          read_amount = min(
              tuf.settings.CHUNK_SIZE, required_length - bytes_received)

          # NOTE: This may not handle some servers adding a Content-Encoding
          # header, which may cause urllib3 to misbehave:
          # https://github.com/pypa/pip/blob/404838abcca467648180b358598c597b74d568c9/src/pip/_internal/download.py#L547-L582
          data = response.raw.read(read_amount)
          bytes_received += len(data)

          yield data

          if bytes_received == required_length:
            break

          # We might have no more data to read. Check number of bytes downloaded.
          if not data:
            logger.debug('Downloaded ' + repr(bytes_received) + '/' +
              repr(required_length) + ' bytes.')

            # Finally, we signal that the download is complete.
            break

      except urllib3.exceptions.ReadTimeoutError as e:
        raise tuf.exceptions.SlowRetrievalError(str(e))




  def _get_session(self, url):
    """
    Returns a different customized requests.Session per schema+hostname
    combination.
    """
    # Use a different requests.Session per schema+hostname combination, to
    # reuse connections while minimizing subtle security issues.
    parsed_url = six.moves.urllib.parse.urlparse(url)

    if not parsed_url.scheme or not parsed_url.hostname:
      raise tuf.exceptions.URLParsingError(
          'Could not get scheme and hostname from URL: ' + url)

    session_index = parsed_url.scheme + '+' + parsed_url.hostname

    logger.debug('url: ' + url)
    logger.debug('session index: ' + session_index)

    session = self._sessions.get(session_index)

    if not session:
      session = requests.Session()
      self._sessions[session_index] = session

      # Attach some default headers to every Session.
      requests_user_agent = session.headers['User-Agent']
      # Follows the RFC: https://tools.ietf.org/html/rfc7231#section-5.5.3
      tuf_user_agent = 'tuf/' + tuf.__version__ + ' ' + requests_user_agent
      session.headers.update({
          # Tell the server not to compress or modify anything.
          # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding#Directives
          'Accept-Encoding': 'identity',
          # The TUF user agent.
          'User-Agent': tuf_user_agent})

      logger.debug('Made new session for ' + session_index)

    else:
      logger.debug('Reusing session for ' + session_index)

    return session