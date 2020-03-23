-- --------------------------------------------------------
-- Host:                         127.0.0.1
-- Server version:               10.4.10-MariaDB - mariadb.org binary distribution
-- Server OS:                    Win64
-- HeidiSQL Version:             10.3.0.5771
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!50503 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;

-- Dumping structure for table test.movie
CREATE TABLE IF NOT EXISTS `movie` (
  `MovieID` varchar(10) NOT NULL,
  `MovieTitle` varchar(30) NOT NULL,
  `ReleaseDate` date NOT NULL,
  `GenereID` varchar(10) DEFAULT NULL,
  `DirectorID` varchar(10) DEFAULT NULL,
  `ImageUrl` varchar(250) NOT NULL,
  `Description` varchar(250) NOT NULL,
  PRIMARY KEY (`MovieID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Dumping data for table test.movie: ~10 rows (approximately)
/*!40000 ALTER TABLE `movie` DISABLE KEYS */;
INSERT INTO `movie` (`MovieID`, `MovieTitle`, `ReleaseDate`, `GenereID`, `DirectorID`, `ImageUrl`, `Description`) VALUES
	('M01', 'Superman vs Batman', '2016-03-25', 'G01', 'D01', 'https://pics.filmaffinity.com/batman_v_superman_dawn_of_justice-728293826-mmed.jpg', 'Batman se enfrenta a Superman, temeroso de que su afán de poder termine nublando su lucha contra la injusticia y lo convierta en un villano. Mientras los héroes pelean, una amenaza terrible se cierne sobre la humanidad.'),
	('M02', 'Deadpool', '2016-02-12', 'G02', 'D02', 'https://pics.filmaffinity.com/deadpool-834516798-mmed.jpg', 'Wade Winston Wilson, más conocido como Deadpool, ? es un personaje ficticio, mercenario, supervillano?? y antihéroe, ? que aparece en los cómics publicados por Marvel Comics. Creado por el artista Rob Liefeld y el escritor Fabian Nicieza, Deadpool ap'),
	('M03', 'Furious 7', '2015-04-03', 'G03', 'D03', 'https://es.web.img3.acsta.net/pictures/15/03/09/12/33/510089.jpg', 'Furious 7 es una película de acción estadounidense de 2015 dirigida por James Wan y protagonizada por Vin Diesel, Paul Walker, Dwayne Johnson, Michelle Rodríguez, Jordana Brewster, Tyrese Gibson, Ludacris y Jason Statham.'),
	('M04', 'PK', '2014-12-19', 'G04', 'D04', 'https://upload.wikimedia.org/wikipedia/en/c/c3/PK_poster.jpg', 'La curiosidad infantil y la visión del mundo de un desconocido desafían las nociones de la gente, haciendo amigos y enemigos a la vez.'),
	('M05', 'Gladiator', '2000-05-05', 'G01', 'D05', 'https://pics.filmaffinity.com/Gladiator-419643516-large.jpg', 'Máximo, general romano, desea volver a casa, pero el emperador Marco Aurelio quiere que herede el imperio. Esto hace que Cómodo ordene matar a su familia. Máximo escapa de la muerte y regresa a Roma como gladiador para vengar la muerte de su familia.'),
	('M06', 'The Hangover', '2009-06-05', 'G02', 'D06', 'https://upload.wikimedia.org/wikipedia/en/b/b9/Hangoverposter09.jpg', 'Dos días antes de su boda, Doug y tres amigos viajan a Las Vegas para una fiesta inolvidable y salvaje. De hecho, cuando los tres acompañantes despiertan la mañana siguiente, no recuerdan nada ni encuentran a Doug. '),
	('M07', '3 Idiots', '2009-12-25', 'G04', 'D04', 'https://images-na.ssl-images-amazon.com/images/I/81kuMqmCTNL._SY445_.jpg', ' Idiots es una película de 2009 dirigida por Rajkumar Hirani y protagonizada por Aamir Khan, R. Madhavan y Sharman Joshi. Está centrada en la amistad de tres estudiantes en una universidad de ingeniería y es una sátira sobre las presiones sociales ba'),
	('M08', 'Spectre', '2015-11-06', 'G03', 'D07', 'https://es.web.img2.acsta.net/pictures/15/09/23/13/00/193624.jpg', 'Un mensaje encriptado de su pasado envía a James Bond en una búsqueda para descubrir a una organización siniestra mientras M se enfrenta a las fuerzas políticas que quieren cerrar el servicio secreto británico.'),
	('M09', 'Batman Begins', '2005-06-15', 'G01', 'D08', 'https://cdn.shopify.com/s/files/1/1416/8662/products/batman_begins_2005_advance_original_film_art_2000x.jpg?v=1574445543', 'Después de la muerte de sus padres, el joven heredero Bruce Wayne se convierte en un vengador enmascarado que lucha contra las fuerzas del mal en Ciudad Gótica.'),
	('M10', 'The Dark Knight', '2008-07-18', 'G05', 'D08', 'https://pics.filmaffinity.com/El_caballero_oscuro-102763119-large.jpg', 'Batman tiene que mantener el equilibrio entre el heroísmo y el vigilantismo para pelear contra un vil criminal conocido como el Guasón, que pretende sumir Ciudad Gótica en la anarquía.');
/*!40000 ALTER TABLE `movie` ENABLE KEYS */;

/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IF(@OLD_FOREIGN_KEY_CHECKS IS NULL, 1, @OLD_FOREIGN_KEY_CHECKS) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
