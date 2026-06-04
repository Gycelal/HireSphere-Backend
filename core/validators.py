from rest_framework import serializers

def validate_profile_picture(image):
    if image.size > 5 * 1024 * 1024:
        raise serializers.ValidationError(
            "Profile picture size should not exceed 5MB."
        )

    if image.content_type not in [
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/jpg",
    ]:
        raise serializers.ValidationError(
            "Only JPEG, PNG, WEBP and JPG images are allowed."
        )

    return image