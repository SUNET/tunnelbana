import time


class RequestTransform:
    def __init__(self, name, base_url, config):
        self.allowed = config["allowed"]

    def process_request(self, context, data):
        data["attributes"]["affiliation"] = self.allowed
        return data


class ResponseTransform:
    def __init__(self, name, base_url, config):
        self.subject = config["subject"]

    def process_response(self, context, data):
        data["subject_id"] = self.subject
        return data


class InternalAttributes:
    def __init__(self, name, base_url, config, internal_attributes):
        del name, base_url, config
        self.internal_attributes = internal_attributes

    def process_response(self, context, data):
        del context
        mail = self.internal_attributes["mail"]["saml"]
        data["attributes"]["mapping-names"] = mail["names"]
        data["attributes"]["mapping-oid"] = [mail["oid"]]
        data["attributes"]["mapping-friendly"] = [mail["friendly_name"]]
        return data


class RequestOnly:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        return data


class RoundTrip:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        expected = {
            "auth_info",
            "requester",
            "requester_name",
            "subject_id",
            "subject_type",
            "attributes",
            "force_authn",
            "is_passive",
        }
        assert set(data) == expected
        assert set(data["auth_info"]) == {"auth_class_ref", "timestamp", "issuer"}
        return data


class ContextMutation:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        context["target_backend"] = "python-selected"
        context["decorations"]["python"] = {"accepted": True}
        return data


class ReadOnlyMutation:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        context["method"] = "DELETE"
        context["target_backend"] = "must-not-commit"
        return data


class MalformedData:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        context["target_backend"] = "must-not-commit"
        # Optional-valued keys must still be present in the complete mapping.
        del data["subject_id"]
        return data


def factory_function(name, base_url, config):
    return RoundTrip(name, base_url, config)


class BackendChooser:
    def __init__(self, name, base_url, config):
        self.backend = config["backend"]

    def process_request(self, context, data):
        context["target_backend"] = self.backend
        return data


class TargetEntityWriter:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        context["decorations"]["target_entity_id"] = "https://python-chosen-idp.example"
        return data


class TargetEntityRemover:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        del context["decorations"]["target_entity_id"]
        return data


class ProviderScopesWriter:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        context["decorations"]["provider_scopes"] = ["untrusted.example"]
        return data


class Raises:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        raise RuntimeError("secret-input-must-not-escape")


class CoroutineMethod:
    def __init__(self, name, base_url, config):
        pass

    async def process_request(self, context, data):
        return data


class AwaitableValue:
    def __await__(self):
        yield
        return None


class AwaitableReturn:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        return AwaitableValue()


class NoMethods:
    def __init__(self, name, base_url, config):
        pass


class NonCallableMethod:
    process_request = 42

    def __init__(self, name, base_url, config):
        pass


class ConstructorFailure:
    def __init__(self, name, base_url, config):
        raise RuntimeError("constructor configuration must not be logged")

    def process_request(self, context, data):
        return data


class ReusedInstance:
    def __init__(self, name, base_url, config):
        self.calls = 0

    def process_request(self, context, data):
        self.calls += 1
        data["subject_id"] = str(self.calls)
        return data


_active = 0
_max_active = 0


class ConcurrencyProbe:
    def __init__(self, name, base_url, config):
        self.wait_seconds = config["wait_seconds"]

    def process_request(self, context, data):
        global _active, _max_active
        _active += 1
        _max_active = max(_max_active, _active)
        # time.sleep releases the GIL. Without the Rust semaphore two calls can
        # overlap here; with a one-permit runtime the observed maximum stays 1.
        time.sleep(self.wait_seconds)
        data["subject_id"] = str(_max_active)
        _active -= 1
        return data


class SlowCall:
    def __init__(self, name, base_url, config):
        self.delay = config["delay"]

    def process_request(self, context, data):
        time.sleep(self.delay)
        return data
