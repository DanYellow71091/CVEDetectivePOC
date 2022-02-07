#!/usr/bin/env python3

import vulners


def get_info():
  vulners_api = vulners.Vulners(api_key="9SI7Z7QBF11OLHOG6HY3QM58RLJL6SP0E2V7NLT8U6IE7AI05KA9HXSUYHVN7K55")

  heartbleed_related = vulners_api.search("heartbleed", limit=10)

  print(heartbleed_related)

def main():
  get_info()

main()
