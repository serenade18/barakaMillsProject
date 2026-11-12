from rest_framework.permissions import BasePermission


class IsAdminRole(BasePermission):
    """Allows access only to users whose role (user_type) is admin.

    Use this instead of DRF's IsAdminUser, which checks is_staff: self-signed-up
    hybrid users have historically been given is_staff=True, so is_staff does
    not mean "admin" in this app. Django superusers are also allowed.
    """

    message = "This action is restricted to admins."

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and (getattr(user, 'user_type', None) == 'admin' or user.is_superuser)
        )
