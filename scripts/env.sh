# shellcheck shell=bash
# scripts/env.sh — load a dotenv file into the environment without executing it.
#
#   source scripts/env.sh && load_env_file .env
#
# `source .env` is unsafe here: values such as ES_JAVA_OPTS=-Xms512m -Xmx512m are
# unquoted (Docker Compose wants them that way) and bash would run "-Xmx512m" as
# a command. This parser exports each KEY=VALUE line literally, strips one pair
# of surrounding quotes, and skips blank lines and comments.
load_env_file() {
  local file="$1" line key val
  [ -f "$file" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    case "$line" in ''|'#'*) continue ;; esac
    line="${line#export }"
    key="${line%%=*}"
    val="${line#*=}"
    [ "$key" != "$line" ] || continue
    key="${key%"${key##*[![:space:]]}"}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    if [[ "$val" =~ ^\"(.*)\"$ ]] || [[ "$val" =~ ^\'(.*)\'$ ]]; then
      val="${BASH_REMATCH[1]}"
    fi
    export "$key=$val"
  done < "$file"
}
