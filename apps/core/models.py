# Import every domain model so the `barakaApp` app config has a models module
# (Django skips content types / permissions for apps without one).
from apps.accounts.models import UserAccount, UserAccountManager, OTP, Role  # noqa: F401
from apps.farmers.models import Farmer  # noqa: F401
from apps.machines.models import Machine  # noqa: F401
from apps.milling.models import Milled  # noqa: F401
from apps.payments.models import Payments  # noqa: F401
