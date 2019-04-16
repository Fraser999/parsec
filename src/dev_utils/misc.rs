// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::{cmp::Ordering, fmt::Debug};
use unwrap::unwrap;

/// Testing related extensions to `Iterator`.
pub trait TestIterator: Iterator {
    /// Returns the only element in the iterator. Panics if the iterator yields less or more than
    /// one element.
    fn only(mut self) -> Self::Item
    where
        Self: Sized,
        Self::Item: Debug,
    {
        let item = unwrap!(self.next(), "Expected one element - got none.");
        assert!(
            self.by_ref().peekable().peek().is_none(),
            "Expected one element - got more (excess: {:?}).",
            self.collect::<Vec<_>>()
        );
        item
    }

    // TODO: Remove this method once the equivalent one in the std lib is stable.
    // https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.is_sorted
    fn itr_is_sorted(mut self) -> bool
    where
        Self: Sized,
        Self::Item: PartialOrd,
    {
        if let Some(mut first) = self.next() {
            for second in self {
                match first.partial_cmp(&second) {
                    Some(Ordering::Less) | Some(Ordering::Equal) => {
                        first = second;
                    }
                    _ => return false,
                }
            }
        }

        true
    }
}

impl<I: Iterator> TestIterator for I {}
