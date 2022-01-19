#!/bin/bash

###
# This script resets modification timestamps of committed files within the repo
# to the last time at which those files were modified in git's history.
# 
# Since gitlab's cached files are timestamped with the cache's creation date
# this allows Makefile's dependency checks (based on file modification time)
# to function properly even across pipelines if build files are cached
#
# Script to set modification times on files taken from this SO post:
# https://stackoverflow.com/a/30143117/1091729
###

last_git_update() {
    # Gives a human readable (iso) string for the last modification time
    # of the provided file
    # Then strips the spaces to provide a string that matches
    # '[[CC]YY]MMDDhhmm[.ss]' (expected by `touch -t`)
    git log --pretty=format:%cd -n 1 --date=iso-local "$1" | sed "s/-//g;s/ //;s/://;s/:/\./;s/ .*//";
}

# Iterate over submodules, setting mtime of all files in submodule to
# last time submodule itself was updated in parent repo
git submodule foreach --quiet 'echo $displaypath' | while read SUBMODULE; do
    LAST_UPDATE="$(last_git_update "$SUBMODULE")";
    echo "Settings timestamps of all files in $SUBMODULE to $LAST_UPDATE"
    cd "$SUBMODULE";
    git ls-files --full-name --directory --recurse-submodules | while read FILE; do
        touch -m -t "$LAST_UPDATE" "$FILE";
    done
    cd - > /dev/null
done

# Set timestamps of all files in main repo to their last modification time in git
echo "Setting timestamps on files in repo"
git ls-files --full-name | while read FILE; do
  UPDATE_TIME="$(last_git_update "$FILE")"
  touch -m -t "$UPDATE_TIME" "$FILE"
done
