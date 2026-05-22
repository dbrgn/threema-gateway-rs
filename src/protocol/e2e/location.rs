//! Location message related types.

use std::{num::ParseFloatError, str::FromStr};

use thiserror::Error;

/// Errors when constructing [`Coordinates`].
#[derive(Debug, PartialEq, Clone, Error)]
pub enum CoordinatesError {
    /// Latitude out of range (must be in `[-90, 90]` and finite)
    #[error("latitude out of range: {0}")]
    LatitudeOutOfRange(f64),

    /// Longitude out of range (must be in `[-180, 180]` and finite)
    #[error("longitude out of range: {0}")]
    LongitudeOutOfRange(f64),
}

/// Errors when parsing a location message.
#[derive(Debug, PartialEq, Clone, Error)]
pub enum LocationMessageParseError {
    /// Missing latitude/longitude coordinates
    #[error("missing coordinates (latitude and longitude are required)")]
    MissingCoordinates,

    /// Invalid latitude value
    #[error("invalid latitude: {0}")]
    InvalidLatitude(#[source] ParseFloatError),

    /// Invalid longitude value
    #[error("invalid longitude: {0}")]
    InvalidLongitude(#[source] ParseFloatError),

    /// Coordinates out of range
    #[error(transparent)]
    InvalidCoordinates(#[from] CoordinatesError),

    /// Invalid accuracy value
    #[error("invalid accuracy: {0}")]
    InvalidAccuracy(#[source] ParseFloatError),

    /// Too many lines in message body
    #[error("too many lines (expected at most 3, got {0})")]
    TooManyLines(usize),
}

/// Errors when interacting with the [`LocationMessageBuilder`].
#[derive(Debug, PartialEq, Clone, Error)]
pub enum LocationMessageBuilderError {
    /// A name was set without an address
    #[error("name requires address to be set")]
    MissingAddress,

    /// Coordinates out of range
    #[error(transparent)]
    InvalidCoordinates(#[from] CoordinatesError),
}

/// WGS-84 coordinates (latitude and longitude).
///
/// Latitude must be in `[-90, 90]` and longitude in `[-180, 180]`. Both must be
/// finite. These invariants are enforced at construction time via
/// [`Coordinates::new`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Coordinates {
    latitude: f64,
    longitude: f64,
}

impl Coordinates {
    /// Create new [`Coordinates`] from a latitude and longitude.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatesError::LatitudeOutOfRange`] if `latitude` is not in
    /// `[-90, 90]` or is non-finite.
    ///
    /// Returns [`CoordinatesError::LongitudeOutOfRange`] if `longitude` is not
    /// in `[-180, 180]` or is non-finite.
    pub fn new(latitude: f64, longitude: f64) -> Result<Self, CoordinatesError> {
        if !latitude.is_finite() || !(-90.0_f64..=90.0_f64).contains(&latitude) {
            return Err(CoordinatesError::LatitudeOutOfRange(latitude));
        }
        if !longitude.is_finite() || !(-180.0_f64..=180.0_f64).contains(&longitude) {
            return Err(CoordinatesError::LongitudeOutOfRange(longitude));
        }
        Ok(Self {
            latitude,
            longitude,
        })
    }

    /// Latitude in WGS-84.
    #[must_use]
    pub fn latitude(&self) -> f64 {
        self.latitude
    }

    /// Longitude in WGS-84.
    #[must_use]
    pub fn longitude(&self) -> f64 {
        self.longitude
    }
}

/// Address information for a location message.
#[derive(Debug, Clone, PartialEq)]
pub struct LocationAddress {
    /// Full address matching the coordinates
    pub address: String,
    /// Name of the point of interest
    pub name: Option<String>,
}

/// A location message.
///
/// Contains geographic coordinates and optional meta information such as an
/// address or a point-of-interest name.
///
/// To construct a [`LocationMessage`], use [`LocationMessageBuilder`] through
/// [`LocationMessage::builder`].
#[derive(Debug, Clone, PartialEq)]
pub struct LocationMessage {
    /// WGS-84 coordinates
    pub coordinates: Coordinates,
    /// Accuracy in meters (should only be set when sending the current device location)
    pub accuracy: Option<f64>,
    /// Address and optional point-of-interest name
    pub address: Option<LocationAddress>,
}

impl LocationMessage {
    /// Create a new [`LocationMessageBuilder`] with the specified coordinates.
    #[must_use]
    pub fn builder(latitude: f64, longitude: f64) -> LocationMessageBuilder {
        LocationMessageBuilder::new(latitude, longitude)
    }

    /// Encode this message to its wire-format UTF-8 bytes.
    ///
    /// Any newlines embedded within the name or address are replaced with the literal `, `.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }
}

impl std::fmt::Display for LocationMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // First line: lat,lon[,accuracy]
        write!(
            f,
            "{},{}",
            self.coordinates.latitude(),
            self.coordinates.longitude()
        )?;
        if let Some(accuracy) = self.accuracy {
            write!(f, ",{accuracy}")?;
        }

        // Optional address
        if let Some(addr) = &self.address {
            if let Some(name) = &addr.name {
                write!(f, "\n{}", name.replace('\n', ", "))?;
            }
            write!(f, "\n{}", addr.address.replace('\n', ", "))?;
        }

        Ok(())
    }
}

impl FromStr for LocationMessage {
    type Err = LocationMessageParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lines: Vec<&str> = s.splitn(4, '\n').collect();

        if lines.len() > 3 {
            return Err(LocationMessageParseError::TooManyLines(
                // Count real line count (splitn(4) gives at most 4 parts; if we
                // got 4 it means there were at least 4 lines)
                s.chars()
                    .filter(|&char| char == '\n')
                    .count()
                    .saturating_add(1),
            ));
        }

        // Parse first line: lat,lon[,accuracy]
        let (coordinates, accuracy) = {
            let coord_line = lines
                .first()
                .ok_or(LocationMessageParseError::MissingCoordinates)?;

            let mut parts = coord_line.splitn(3, ',');

            let lat_str = parts
                .next()
                .ok_or(LocationMessageParseError::MissingCoordinates)?;
            let lon_str = parts
                .next()
                .ok_or(LocationMessageParseError::MissingCoordinates)?;

            let latitude = lat_str
                .trim()
                .parse::<f64>()
                .map_err(LocationMessageParseError::InvalidLatitude)?;
            let longitude = lon_str
                .trim()
                .parse::<f64>()
                .map_err(LocationMessageParseError::InvalidLongitude)?;

            let coordinates = Coordinates::new(latitude, longitude)?;

            let accuracy = parts
                .next()
                .map(|acc_str| {
                    acc_str
                        .trim()
                        .parse::<f64>()
                        .map_err(LocationMessageParseError::InvalidAccuracy)
                })
                .transpose()?;

            (coordinates, accuracy)
        };

        // Parse optional name / address lines
        #[expect(clippy::indexing_slicing, reason = "Validated through line counting")]
        let address = match lines.len() {
            1 => None,
            2 => {
                // Single optional line -> address
                Some(LocationAddress {
                    address: lines[1].to_owned(),
                    name: None,
                })
            }
            3 => {
                // Two optional lines -> name + address
                Some(LocationAddress {
                    address: lines[2].to_owned(),
                    name: Some(lines[1].to_owned()),
                })
            }
            _ => unreachable!("splitn(4) returns at most 4 parts; >3 is handled above"),
        };

        Ok(LocationMessage {
            coordinates,
            accuracy,
            address,
        })
    }
}

/// Builder for [`LocationMessage`]. Instantiate through [`LocationMessage::builder`].
pub struct LocationMessageBuilder {
    latitude: f64,
    longitude: f64,
    accuracy: Option<f64>,
    name: Option<String>,
    address: Option<String>,
}

impl LocationMessageBuilder {
    /// Create a new [`LocationMessageBuilder`] with the specified coordinates.
    pub(crate) fn new(latitude: f64, longitude: f64) -> Self {
        LocationMessageBuilder {
            latitude,
            longitude,
            accuracy: None,
            name: None,
            address: None,
        }
    }

    /// Set the accuracy in meters.
    ///
    /// Should only be set when sending the current location of a device.
    #[must_use]
    pub fn accuracy(mut self, accuracy: f64) -> Self {
        self.accuracy = Some(accuracy);
        self
    }

    /// Set the accuracy from an Option.
    #[must_use]
    pub fn accuracy_opt(mut self, accuracy: Option<f64>) -> Self {
        self.accuracy = accuracy;
        self
    }

    /// Set the address.
    #[must_use]
    pub fn address<A: Into<String>>(self, address: A) -> Self {
        self.address_opt(Some(address))
    }

    /// Set the address from an Option.
    #[must_use]
    pub fn address_opt<A: Into<String>>(mut self, address: Option<A>) -> Self {
        self.address = address.map(Into::into);
        self
    }

    /// Set the point-of-interest name.
    ///
    /// Requires an address to also be set (either via [`address`](Self::address) or
    /// [`address_opt`](Self::address_opt)). [`build`](Self::build) will return a
    /// [`LocationMessageBuilderError::MissingAddress`] error if a name is set without an address.
    #[must_use]
    pub fn name<N: Into<String>>(self, name: N) -> Self {
        self.name_opt(Some(name))
    }

    /// Set the point-of-interest name from an Option.
    #[must_use]
    pub fn name_opt<N: Into<String>>(mut self, name: Option<N>) -> Self {
        self.name = name.map(Into::into);
        self
    }

    /// Build the [`LocationMessage`].
    ///
    /// # Errors
    ///
    /// - [`LocationMessageBuilderError::InvalidCoordinates`] if the latitude is not in `[-90, 90]`
    ///   or the longitude is not in `[-180, 180]` (or either is non-finite).
    /// - [`LocationMessageBuilderError::MissingAddress`] if a name was set without an address.
    pub fn build(self) -> Result<LocationMessage, LocationMessageBuilderError> {
        let coordinates = Coordinates::new(self.latitude, self.longitude)?;
        if self.name.is_some() && self.address.is_none() {
            return Err(LocationMessageBuilderError::MissingAddress);
        }
        let address = self.address.map(|address| LocationAddress {
            address,
            name: self.name,
        });
        Ok(LocationMessage {
            coordinates,
            accuracy: self.accuracy,
            address,
        })
    }
}

#[cfg(test)]
#[expect(
    clippy::float_cmp,
    clippy::default_numeric_fallback,
    reason = "Allowed in tests"
)]
mod tests {
    use super::*;

    mod coordinates {
        use super::*;

        #[test]
        fn valid() {
            let coords = Coordinates::new(47.3769, 8.5417).unwrap();
            assert_eq!(coords.latitude(), 47.3769);
            assert_eq!(coords.longitude(), 8.5417);
        }

        #[test]
        fn boundary_latitude() {
            let coords = Coordinates::new(-90.0, 0.0).unwrap();
            assert_eq!(coords.latitude(), -90.0);
            let coords = Coordinates::new(90.0, 0.0).unwrap();
            assert_eq!(coords.latitude(), 90.0);
        }

        #[test]
        fn boundary_longitude() {
            let coords = Coordinates::new(0.0, -180.0).unwrap();
            assert_eq!(coords.longitude(), -180.0);
            let coords = Coordinates::new(0.0, 180.0).unwrap();
            assert_eq!(coords.longitude(), 180.0);
        }

        #[test]
        fn latitude_out_of_range() {
            let err = Coordinates::new(90.1, 0.0).unwrap_err();
            assert_eq!(err, CoordinatesError::LatitudeOutOfRange(90.1));

            let err = Coordinates::new(-90.1, 0.0).unwrap_err();
            assert_eq!(err, CoordinatesError::LatitudeOutOfRange(-90.1));
        }

        #[test]
        fn longitude_out_of_range() {
            let err = Coordinates::new(0.0, 180.1).unwrap_err();
            assert_eq!(err, CoordinatesError::LongitudeOutOfRange(180.1));

            let err = Coordinates::new(0.0, -180.1).unwrap_err();
            assert_eq!(err, CoordinatesError::LongitudeOutOfRange(-180.1));
        }

        #[test]
        fn nan_latitude() {
            let err = Coordinates::new(f64::NAN, 0.0).unwrap_err();
            assert!(
                matches!(err, CoordinatesError::LatitudeOutOfRange(val) if val.is_nan()),
                "expected LatitudeOutOfRange(NaN), got {err:?}"
            );
        }

        #[test]
        fn nan_longitude() {
            let err = Coordinates::new(0.0, f64::NAN).unwrap_err();
            assert!(
                matches!(err, CoordinatesError::LongitudeOutOfRange(val) if val.is_nan()),
                "expected LongitudeOutOfRange(NaN), got {err:?}"
            );
        }

        #[test]
        fn infinite_latitude() {
            let err = Coordinates::new(f64::INFINITY, 0.0).unwrap_err();
            assert_eq!(err, CoordinatesError::LatitudeOutOfRange(f64::INFINITY));
        }

        #[test]
        fn infinite_longitude() {
            let err = Coordinates::new(0.0, f64::NEG_INFINITY).unwrap_err();
            assert_eq!(
                err,
                CoordinatesError::LongitudeOutOfRange(f64::NEG_INFINITY)
            );
        }
    }

    mod builder {
        use super::*;

        #[test]
        fn minimal() {
            let msg = LocationMessage::builder(47.3769, 8.5417).build().unwrap();
            assert_eq!(msg.coordinates.latitude(), 47.3769_f64);
            assert_eq!(msg.coordinates.longitude(), 8.5417_f64);
            assert!(msg.accuracy.is_none());
            assert!(msg.address.is_none());
        }

        #[test]
        fn with_accuracy() {
            let msg = LocationMessage::builder(47.3769, 8.5417)
                .accuracy(12.5)
                .build()
                .unwrap();
            assert_eq!(msg.accuracy, Some(12.5));
        }

        #[test]
        fn with_address() {
            let msg = LocationMessage::builder(47.3769, 8.5417)
                .address("Bahnhofstrasse 1, 8001 Zürich")
                .build()
                .unwrap();
            let addr = msg.address.as_ref().expect("address should be set");
            assert_eq!(addr.address, "Bahnhofstrasse 1, 8001 Zürich");
            assert!(addr.name.is_none());
        }

        #[test]
        fn with_name_and_address() {
            let msg = LocationMessage::builder(47.3769, 8.5417)
                .name("Zürich HB")
                .address("Bahnhofplatz, 8001 Zürich")
                .build()
                .unwrap();
            let addr = msg.address.as_ref().expect("address should be set");
            assert_eq!(addr.name.as_deref(), Some("Zürich HB"));
            assert_eq!(addr.address, "Bahnhofplatz, 8001 Zürich");
        }

        #[test]
        fn latitude_out_of_range() {
            let err = LocationMessage::builder(91.0, 0.0).build().unwrap_err();
            assert_eq!(
                err,
                LocationMessageBuilderError::InvalidCoordinates(
                    CoordinatesError::LatitudeOutOfRange(91.0)
                )
            );
        }

        #[test]
        fn longitude_out_of_range() {
            let err = LocationMessage::builder(0.0, 181.0).build().unwrap_err();
            assert_eq!(
                err,
                LocationMessageBuilderError::InvalidCoordinates(
                    CoordinatesError::LongitudeOutOfRange(181.0)
                )
            );
        }

        #[test]
        fn name_without_address_is_error() {
            let err = LocationMessage::builder(47.3769, 8.5417)
                .name("Some POI")
                .build()
                .unwrap_err();
            assert_eq!(err, LocationMessageBuilderError::MissingAddress);
        }

        #[test]
        fn accuracy_opt_none() {
            let msg = LocationMessage::builder(1.0, 2.0)
                .accuracy_opt(None)
                .build()
                .unwrap();
            assert!(msg.accuracy.is_none());
        }

        #[test]
        fn address_opt_none() {
            let msg = LocationMessage::builder(1.0, 2.0)
                .address_opt::<String>(None)
                .build()
                .unwrap();
            assert!(msg.address.is_none());
        }

        #[test]
        fn name_opt_none_with_no_address() {
            // name_opt(None) + no address -> OK (None name does not trigger error)
            let msg = LocationMessage::builder(1.0, 2.0)
                .name_opt::<String>(None)
                .build()
                .unwrap();
            assert!(msg.address.is_none());
        }
    }

    mod encode {
        use super::*;

        #[test]
        fn coordinates_only() {
            let msg = LocationMessage::builder(47.3769, 8.5417).build().unwrap();
            assert_eq!(msg.to_string(), "47.3769,8.5417");
        }

        #[test]
        fn with_accuracy() {
            let msg = LocationMessage::builder(47.3769, 8.5417)
                .accuracy(12.5)
                .build()
                .unwrap();
            assert_eq!(msg.to_string(), "47.3769,8.5417,12.5");
        }

        #[test]
        fn with_address() {
            let msg = LocationMessage::builder(47.3769, 8.5417)
                .address("Bahnhofstrasse 1, 8001 Zürich")
                .build()
                .unwrap();
            assert_eq!(
                msg.to_string(),
                "47.3769,8.5417\nBahnhofstrasse 1, 8001 Zürich"
            );
        }

        #[test]
        fn with_name_and_address() {
            let msg = LocationMessage::builder(47.3769, 8.5417)
                .name("Zürich HB")
                .address("Bahnhofplatz, 8001 Zürich")
                .build()
                .unwrap();
            assert_eq!(
                msg.to_string(),
                "47.3769,8.5417\nZürich HB\nBahnhofplatz, 8001 Zürich"
            );
        }

        #[test]
        fn address_with_embedded_newline_is_replaced() {
            let msg = LocationMessage::builder(1.0, 2.0)
                .address("Line 1\nLine 2\nLine 3")
                .build()
                .unwrap();
            assert_eq!(msg.to_string(), "1,2\nLine 1, Line 2, Line 3");
        }

        #[test]
        fn encode_returns_utf8_bytes() {
            let msg = LocationMessage::builder(1.0, 2.0).build().unwrap();
            assert_eq!(msg.encode(), b"1,2");
        }

        #[test]
        fn negative_coordinates() {
            let msg = LocationMessage::builder(-33.8688, 151.2093)
                .build()
                .unwrap();
            assert_eq!(msg.to_string(), "-33.8688,151.2093");
        }
    }

    mod parse {
        use super::*;

        #[test]
        fn coordinates_only() {
            let msg: LocationMessage = "47.3769,8.5417".parse().unwrap();
            assert_eq!(msg.coordinates.latitude(), 47.3769);
            assert_eq!(msg.coordinates.longitude(), 8.5417);
            assert!(msg.accuracy.is_none());
            assert!(msg.address.is_none());
        }

        #[test]
        fn with_accuracy() {
            let msg: LocationMessage = "47.3769,8.5417,12.5".parse().unwrap();
            assert_eq!(msg.coordinates.latitude(), 47.3769);
            assert_eq!(msg.coordinates.longitude(), 8.5417);
            assert_eq!(msg.accuracy, Some(12.5));
        }

        #[test]
        fn with_address() {
            let msg: LocationMessage = "47.3769,8.5417\nBahnhofstrasse 1, 8001 Zürich"
                .parse()
                .unwrap();
            assert_eq!(msg.coordinates.latitude(), 47.3769);
            let addr = msg.address.as_ref().expect("address should be set");
            assert_eq!(addr.address, "Bahnhofstrasse 1, 8001 Zürich");
            assert!(addr.name.is_none());
        }

        #[test]
        fn with_accuracy_and_address() {
            let msg: LocationMessage = "47.3769,8.5417,10.0\nSome Street 1".parse().unwrap();
            assert_eq!(msg.accuracy, Some(10.0));
            let addr = msg.address.as_ref().expect("address should be set");
            assert_eq!(addr.address, "Some Street 1");
        }

        #[test]
        fn with_name_and_address() {
            let msg: LocationMessage = "47.3769,8.5417\nZürich HB\nBahnhofplatz, 8001 Zürich"
                .parse()
                .unwrap();
            let addr = msg.address.as_ref().expect("address should be set");
            assert_eq!(addr.name.as_deref(), Some("Zürich HB"));
            assert_eq!(addr.address, "Bahnhofplatz, 8001 Zürich");
        }

        #[test]
        fn negative_coordinates() {
            let msg: LocationMessage = "-33.8688,151.2093".parse().unwrap();
            assert_eq!(msg.coordinates.latitude(), -33.8688);
            assert_eq!(msg.coordinates.longitude(), 151.2093);
        }

        #[test]
        fn invalid_latitude() {
            let err = "91.0,8.5417".parse::<LocationMessage>().unwrap_err();
            assert_eq!(
                err,
                LocationMessageParseError::InvalidCoordinates(
                    CoordinatesError::LatitudeOutOfRange(91.0)
                )
            );
        }

        #[test]
        fn nan_longitude() {
            let err = "47.3769,NaN".parse::<LocationMessage>().unwrap_err();
            assert!(
                matches!(
                    err,
                    LocationMessageParseError::InvalidCoordinates(
                        CoordinatesError::LongitudeOutOfRange(val)
                    ) if val.is_nan()
                ),
                "expected LongitudeOutOfRange(NaN), got {err:?}"
            );
        }

        #[test]
        fn too_many_lines() {
            let input = "1,2\nname\naddress\nextra";
            let err = input.parse::<LocationMessage>().unwrap_err();
            assert!(
                matches!(err, LocationMessageParseError::TooManyLines(_)),
                "expected TooManyLines, got {err:?}"
            );
        }

        #[test]
        fn missing_longitude() {
            let err = "47.3769".parse::<LocationMessage>().unwrap_err();
            assert!(
                matches!(err, LocationMessageParseError::MissingCoordinates),
                "expected MissingCoordinates, got {err:?}"
            );
        }

        #[test]
        fn non_float_latitude() {
            let err = "abc,8.5417".parse::<LocationMessage>().unwrap_err();
            assert!(
                matches!(err, LocationMessageParseError::InvalidLatitude(_)),
                "expected InvalidLatitude, got {err:?}"
            );
        }

        #[test]
        fn non_float_longitude() {
            let err = "47.3769,xyz".parse::<LocationMessage>().unwrap_err();
            assert!(
                matches!(err, LocationMessageParseError::InvalidLongitude(_)),
                "expected InvalidLongitude, got {err:?}"
            );
        }

        #[test]
        fn non_float_accuracy() {
            let err = "47.3769,8.5417,bad".parse::<LocationMessage>().unwrap_err();
            assert!(
                matches!(err, LocationMessageParseError::InvalidAccuracy(_)),
                "expected InvalidAccuracy, got {err:?}"
            );
        }
    }

    mod round_trip {
        use super::*;

        fn assert_round_trip(msg: &LocationMessage) {
            let encoded = msg.to_string();
            let decoded: LocationMessage = encoded.parse().expect("round-trip parse failed");
            assert_eq!(decoded, *msg);
        }

        #[test]
        fn coordinates_only() {
            let msg = LocationMessage::builder(47.3769, 8.5417).build().unwrap();
            assert_round_trip(&msg);
        }

        #[test]
        fn with_accuracy() {
            let msg = LocationMessage::builder(47.3769, 8.5417)
                .accuracy(12.5)
                .build()
                .unwrap();
            assert_round_trip(&msg);
        }

        #[test]
        fn with_address() {
            let msg = LocationMessage::builder(47.3769, 8.5417)
                .address("Bahnhofstrasse 1, 8001 Zürich")
                .build()
                .unwrap();
            assert_round_trip(&msg);
        }

        #[test]
        fn with_name_and_address() {
            let msg = LocationMessage::builder(47.3769, 8.5417)
                .name("Zürich HB")
                .address("Bahnhofplatz, 8001 Zürich")
                .build()
                .unwrap();
            assert_round_trip(&msg);
        }

        #[test]
        fn full() {
            let msg = LocationMessage::builder(-33.8688, 151.2093)
                .accuracy(5.0)
                .name("Sydney Opera House")
                .address("Bennelong Point, Sydney NSW 2000")
                .build()
                .unwrap();
            assert_round_trip(&msg);
        }
    }
}
