# Copyright (C) 2016 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


class OvnK8sException(Exception):

    def __init__(self, **kwargs):
        self.message = self.message % kwargs
        super(OvnK8sException, self).__init__(self.message)


class NotFound(OvnK8sException):
    message = "%(resource_type)s %(resource_id)s not found"


class APIServerTimeout(OvnK8sException):
    message = "API server stream connection failed"
