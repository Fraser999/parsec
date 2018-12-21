// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::mem;

/// Split a Vec<T> into chunks, where the element matched by the predicate is the first in each
/// chunk.
pub fn split_on_first<F, T>(items: Vec<T>, predicate: F) -> SplitOnFirst<T, F>
where
    F: FnMut(&T) -> bool,
{
    SplitOnFirst { items, predicate }
}

pub struct SplitOnFirst<T, P>
where
    P: FnMut(&T) -> bool,
{
    items: Vec<T>,
    predicate: P,
}

impl<T, P> Iterator for SplitOnFirst<T, P>
where
    P: FnMut(&T) -> bool,
{
    type Item = Vec<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.items.is_empty() {
            return None;
        }

        // Since the matched element is the first in the second chunk, we need to skip index == 0.
        let mut index = 1;
        while index < self.items.len() {
            if (self.predicate)(&self.items[index]) {
                break;
            } else {
                index += 1;
            }
        }

        let new_items = self.items.split_off(index);
        Some(mem::replace(&mut self.items, new_items))
    }
}

#[cfg(test)]
mod tests {
    use super::super::split_on_first;

    #[test]
    fn split_vec_of_numbers() {
        assert_eq!(
            split_on_first(vec![1, 2, 3, 4, 5, 6, 7], |n| n % 2 == 0).collect::<Vec<Vec<_>>>(),
            vec![vec![1], vec![2, 3], vec![4]]
        )
    }
}
