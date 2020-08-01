require 'yaml'

config = YAML.load(STDIN)

image = config["jobs"]["test"]["docker"][0]["image"]
if !image.start_with?("cimg/go:")
  raise "unknown image #{image} in #{configPath}"
end

goVersion = image.delete_prefix("cimg/go:")
print(goVersion)
