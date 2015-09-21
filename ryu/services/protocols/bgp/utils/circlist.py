# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from six.moves import intern


class CircularListType(object):
    """Instances of this class represent a specific type of list.
    Nodes are linked in a circular fashion, using attributes on the
    nodes themselves.

    Example:

      ItemList = CircularListType(next_attr='_next',
                                  prev_attr='_prev')

      l = ItemList()
      l.prepend(item)

    The created list has the following properties:

      - A node can be inserted O(1) time at the head, tail, or
        after/before another specified node.

      - A node can be removed in O(1) time from any list it may be on,
        without providing a reference to the list.

      - The current node in an iteration can be deleted safely.

     """

    class List(object):
        """An object that represents a list.

        This class is not expected to be used directly by clients. Rather, they
        would use the 'create' method of a CircularListType object to create an
        instance.
        """

        # Define the set of valid attributes so as to make the list
        # head lightweight.
        #
        # We override __getattr__ and __setattr__ so as to store the
        # the next and previous references on the list head in
        # _next_slot_ and _prev_slot_ respectively.
        __slots__ = ["list_type", "head", "_next_slot_",
                     "_prev_slot_"]

        def __init__(self, list_type):
            self.list_type = list_type

            # Save memory by using the List object itself as the head.
            self.head = self
            self.list_type.node_init(self.head)

        def __getattr__(self, name):
            if(name == self.list_type.next_name):
                return self._next_slot_

            if(name == self.list_type.prev_name):
                return self._prev_slot_

            raise AttributeError(name)

        def __setattr__(self, name, value):
            if(name in CircularListType.List.__slots__):
                object.__setattr__(self, name, value)
                return

            if(name == self.list_type.next_name):
                self._next_slot_ = value
                return

            if(name == self.list_type.prev_name):
                self._prev_slot_ = value
                return

            raise AttributeError(name)

        def is_empty(self):
            return not self.list_type.node_is_on_list(self.head)

        def clear(self):
            """Remove all items from the list."""

            # Make sure that all items are unlinked.
            for node in self:
                self.remove(node)

        def is_on_list(self, node):
            return self.list_type.node_is_on_list(node)

        def append(self, node):
            self.list_type.node_insert_before(self.head, node)

        def prepend(self, node):
            self.list_type.node_insert_after(self.head, node)

        def __iter__(self):
            return self.generator()

        def remove(self, node):
            """List the given node from the list.

            Note that this does not verify that the node is on this
            list. It could even be on a different list.
            """
            self.list_type.node_unlink(node)

            self.list_type.node_del_attrs(node)

        def pop_first(self):
            """Remove the first item in the list and return it."""
            node = self.list_type.node_next(self.head)
            if(node is self.head):
                return None

            self.remove(node)
            return node

        def generator(self):
            """Enables iteration over the list.

            The current item can safely be removed from the list during
            iteration.
            """
            # Keep a pointer to the next node when returning the
            # current node. This allows the caller to remove the
            # current node safely.
            node = self.list_type.node_next(self.head)
            next = self.list_type.node_next(node)
            while(node is not self.head):
                yield node

                node = next
                next = self.list_type.node_next(node)

    #
    # CircularListType methods
    #

    def __init__(self, next_attr_name=None, prev_attr_name=None):
        """Initializes this list.

        next_attr_name: The name of the attribute that holds a reference
                        to the next item in the list.

        prev_attr_name: the name of the attribute that holds a reference
                        to the previous item in the list.
        """

        # Keep an interned version of the attribute names. This should
        # speed up the process of looking up the attributes.
        self.next_name = intern(next_attr_name)
        self.prev_name = intern(prev_attr_name)

    def create(self):
        return CircularListType.List(self)

    def __call__(self):
        """Make a CircularListType instance look like a class by
        creating a list object.
        """
        return self.create()

    def node_init(self, node):
        assert(not self.node_is_on_list(node))

        # Set the node to point to itself as the previous and next
        # entries.
        self.node_set_next(node, node)
        self.node_set_prev(node, node)

    def node_next(self, node):
        try:
            return getattr(node, self.next_name)
        except AttributeError:
            return None

    def node_set_next(self, node, next):
        setattr(node, self.next_name, next)

    def node_prev(self, node):
        try:
            return getattr(node, self.prev_name)
        except AttributeError:
            return None

    def node_set_prev(self, node, prev):
        setattr(node, self.prev_name, prev)

    def node_del_attrs(self, node):
        """Remove all attributes that are used for putting this node
        on this type of list.
        """
        try:
            delattr(node, self.next_name)
            delattr(node, self.prev_name)
        except AttributeError:
            pass

    def node_is_on_list(self, node):
        """Returns True if this node is on *some* list.

        A node is not on any list if it is linked to itself, or if it
        does not have the next and/prev attributes at all.
        """
        next = self.node_next(node)
        if next == node or next is None:
            assert(self.node_prev(node) is next)
            return False

        return True

    def node_insert_after(self, node, new_node):
        """Insert the new node after node."""

        assert(not self.node_is_on_list(new_node))
        assert(node is not new_node)

        next = self.node_next(node)
        assert(next is not None)
        self.node_set_next(node, new_node)
        self.node_set_prev(new_node, node)

        self.node_set_next(new_node, next)
        self.node_set_prev(next, new_node)

    def node_insert_before(self, node, new_node):
        """Insert the new node before node."""

        assert(not self.node_is_on_list(new_node))
        assert(node is not new_node)

        prev = self.node_prev(node)
        assert(prev is not None)
        self.node_set_prev(node, new_node)
        self.node_set_next(new_node, node)

        self.node_set_prev(new_node, prev)
        self.node_set_next(prev, new_node)

    def node_unlink(self, node):

        if not self.node_is_on_list(node):
            return

        prev = self.node_prev(node)
        next = self.node_next(node)

        self.node_set_next(prev, next)
        self.node_set_prev(next, prev)

        self.node_set_next(node, node)
        self.node_set_prev(node, node)
